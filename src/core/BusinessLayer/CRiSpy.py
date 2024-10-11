#!/usr/bin/python
# ---------------------------------------------------------------------------------------------------------------------
# Crispy.py
#
# Author      : Peter Heijligers
# Description : Code Review involving Search patterns
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import fnmatch

import src.core.Functions.FindProject as findProject
import src.core.Functions.Functions as findCompany
from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.CVEManager import CVEManager
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.BusinessLayer.FrameworkManager import FrameworkManager
from src.core.BusinessLayer.ProgramLanguageManager import ProgramLanguageManager
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.core.BusinessLayer.SecurityHeadersManager import SecurityHeadersManager
from src.core.BusinessLayer.SecurityOmissionsManager import SecurityOmissionsManager
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.CoreModel import FD
from src.core.DataLayer.Enums import ETLAction
from src.core.DataLayer.SearchPattern import SearchPattern
from src.gl.BusinessLayer import TimeManager
from src.gl.BusinessLayer.ConfigManager import *
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.BusinessLayer.TimeManager import time_exec
from src.gl.Const import CATEGORY_COMPANY, SEARCH_DATA_PATH, APP_NAME, DONE, MAX_PATTERN_LENGTH_AT_QUICK_SCAN, \
    GREEN, BLUE, ANY
from src.gl.Enums import *
from src.gl.Functions import replace_root_in_path, remove_empty_folders, list_to_string, \
    sanitize_text_to_alphanum_and_underscore, is_internet_facing
from src.gl.Message import Message
from src.gl.Validate import *

errorTextNC = "Error: "
errorText = f'{Color.RED}{errorTextNC}{Color.NC}'

# Instances
CM = ConfigManager()
SP_manager = SearchPattern_Manager()
LA_manager = ProgramLanguageManager()
FW_manager = FrameworkManager()
FM = Findings_Manager()

log = Log()


class CRiSpy(object):

    @property
    def error_message(self):
        return self._error_message

    @property
    def input_dir(self):
        return self._input_dir

    @property
    def application_type(self):
        return self._application_type

    @property
    def title(self):
        return self._title

    @property
    def company_name(self):
        return self._company_name

    @property
    def custom_pattern(self):
        return self._custom_pattern

    @property
    def verbose(self):
        return self._verbose

    @property
    def filter_mode(self):
        return self._filter_mode

    @property
    def quick_scan(self):
        return self._quick_scan

    @property
    def cli_mode(self):
        return self._cli_mode

    @property
    def synchronize_cve(self):
        return self._synchronize_cve

    @property
    def output(self):
        return self._output

    @property
    def output_dir(self):
        return self._output_dir

    @property
    def data_dir(self):
        return self._data_dir

    @property
    def project_name(self):
        return self._project_name

    @property
    def exec_type(self):
        return self._exec_type

    @property
    def excluded_dir_names(self):
        return self._excluded_dir_names

    @property
    def excluded_file_names(self):
        return self._excluded_file_names

    @property
    def sane_if_pattern_in(self):
        return self._sane_if_pattern_in

    @property
    def time_exec_threshold_ms(self):
        return self._time_exec_threshold_ms

    @property
    def time_exec_max_ms(self):
        return self._time_exec_max_ms

    @property
    def debug_path(self):
        return self._debug_path

    @property
    def debug_pattern_name(self):
        return self._output_dir

    def __init__(self,
                 input_dir,
                 application_type=ApplicationTypeEnum.Any,
                 log_title=EMPTY,
                 company_name=ANY,
                 custom_search_pattern=EMPTY,
                 verbose=False,
                 filter_findings=True,
                 quick_scan=False,
                 cli_mode=False,
                 synchronize_cve=True,
                 output_type=LogType.Both,
                 output_dir=EMPTY,
                 data_dir=EMPTY,
                 project_name=EMPTY,
                 exec_type=ExecTypeEnum.Both,
                 excluded_dir_names=EMPTY,
                 excluded_file_names=EMPTY,
                 sane_if_pattern_in=EMPTY,
                 time_exec_threshold_ms=0,
                 time_exec_max_ms=0,
                 debug_path=EMPTY,
                 debug_pattern_name=EMPTY
                 ):
        self._input_dir = input_dir
        self._application_type = application_type
        self._title = log_title
        self._company_name = company_name
        self._scanner = None

        # Pattern may be object or string
        self._sp = None
        if isinstance(custom_search_pattern, SearchPattern):
            self._sp = custom_search_pattern
            self._custom_pattern = custom_search_pattern.pattern
        else:
            self._custom_pattern = custom_search_pattern

        # Parameters
        self._verbose = verbose
        self._filter_mode = filter_findings
        self._cli_mode = cli_mode
        self._quick_scan = quick_scan
        self._synchronize_cve = synchronize_cve
        self._output = output_type
        self._one_pattern = True if custom_search_pattern else False
        self._project_name = project_name
        self._exec_type = exec_type
        self._output_dir = output_dir
        self._data_dir = data_dir
        self._time_exec_threshold_ms = time_exec_threshold_ms
        self._time_exec_max_ms = time_exec_max_ms
        self._excluded_dir_names = excluded_dir_names
        self._excluded_file_names = excluded_file_names
        self._sane_if_pattern_in = sane_if_pattern_in
        self._debug_path = debug_path
        self._debug_pattern_name = debug_pattern_name

        self._xref = exec_type in (ExecTypeEnum.Both, ExecTypeEnum.DataFlow)
        self._interactive = False
        self._log_started = False
        self._companies = []
        self._has_db = False
        self._log_level = None
        self._unit_test = False
        self._session = None
        self._error_message = None
        self._search_patterns = []
        self._cve_manager = None

    def start(self, unit_test=False) -> Result:
        """
        Main line
        """
        try:
            self._unit_test = unit_test

            result = self._validate_input()
            if not result.OK:
                return result

            # Write config
            CM.write_config()

            # Start _log
            self._start_log()

            # User confirmation
            if self._get_interactive() and not ui.is_confirmative():
                return Result(ResultCode.Error, self._error_message)

            """ Synchronize from NIST """
            if (self._synchronize_cve is True and self._one_pattern is False
                    and self._exec_type in (ExecTypeEnum.DataFlow, ExecTypeEnum.Both)):
                try:
                    # Synchronize *CVE.csv from NIST
                    self._cve_manager = CVEManager(check_only=False, cli_mode=self._cli_mode)
                    self._cve_manager.synchronize()
                except GeneralException as e:
                    self._log(e.message, error=True)

            """ Scan """
            if self._exec_type in (ExecTypeEnum.Scan, ExecTypeEnum.Both):
                if not self._scan():
                    return Result(ResultCode.Error, self._error_message)
                self._write_scan_results()
                self._set_findings_manager()

            #  1-pattern mode: ready and return
            if self._one_pattern:
                return self._wrap_up()

            """ XRef """
            if self._exec_type in (ExecTypeEnum.DataFlow, ExecTypeEnum.Both):
                if self._session.db and not self._quick_scan and self._xref:
                    if not self._scanner.scanned_paths:
                        self._scanner.scan()
                    from src.db.BusinessLayer.XRef.XRefManager import XRefManager
                    XR = XRefManager(self._session.db)
                    XR.build_xref(self._scanner.base_dir, self._scanner.scanned_paths)

            """ Plug-ins (after X-Ref) """
            self._plugins()

            """ Omissions and headers (after Plug-ins) """
            if self._exec_type in (ExecTypeEnum.Scan, ExecTypeEnum.Both):
                supported = [ft.replace('.', EMPTY) for ft in self._scanner.included_file_types
                             if ft in LA_manager.language_dict and ft != '.html']

                # Security Omissions
                som = SecurityOmissionsManager(self._scanner)
                [som.start(self._application_type, file_type=ft) for ft in supported]
                self._completion_messages('Security patterns that are not found:', som.messages)

                # Security Headers
                if is_internet_facing(self._application_type):
                    shm = SecurityHeadersManager()
                    [shm.start(self._scanner, file_type=ft, language_manager=LA_manager) for ft in supported]
                    self._completion_messages('Security headers:', shm.messages)

            return self._wrap_up()

        except GeneralException as e:
            return Result(ResultCode.Error, e.message)

    def _validate_input(self) -> Result:
        # Input dir must exist and not too short
        if not os.path.isdir(self._input_dir):
            return Result(ResultCode.Error, f"{get_label(CF_INPUT_DIR)} '{self._input_dir}' does not exist.")
        if len(self._input_dir) < 2:
            return Result(ResultCode.Error, f"{get_label(CF_INPUT_DIR)} '{self._input_dir}' is too short.")

        CM.config_dict[CF_INPUT_DIR] = self._input_dir

        self._session = self._configure_session()
        self._has_db = self._session.has_db

        # Configure basic user input
        if not self._configure_input():
            return Result(ResultCode.Error, self._error_message)

        # Interactive vs. automatic
        if self._get_interactive() and not self._get_user_input():
            return Result(ResultCode.Error, self._error_message)

        # Validate all user provided input
        self._validate_user_input()

        # Log type
        CM.config_dict[CF_OUTPUT_TYPE] = self._output \
            if self._output in [LogType.File, LogType.Stdout] else LogType.Both

        # Quick scan (= exclude complex regex to fetch email)
        CM.config_dict[CF_QUICK_SCAN] = True if self._quick_scan else False

        # Sync CVE
        CM.config_dict[CF_SYNC_CVE] = True if self._synchronize_cve else False

        # Connect to DB
        if self._has_db and not self._one_pattern:
            from src.db.DataLayer.DBInitialize import DBInitialize as DBInit
            dbInit = DBInit()
            # a. Connect (and set session.db and build db if empty)
            if not dbInit.connect():
                return Result(ResultCode.Error, messages=dbInit.messages)
            # b. CLI mode: SetUp db if needed.
            if self._cli_mode:
                if not dbInit.is_consistent() and not dbInit.is_consistent(force=True):
                    return Result(ResultCode.Error, messages=dbInit.messages)

        # Analyze which file_types are present in the input directory.

        self._scanner = Scanner.Scanner(
            self._input_dir, file_type='*', db=self._session.db, quick_scan=self._quick_scan,
            debug_path=self._debug_path)
        if not self._scanner:
            return Result(ResultCode.Error, 'Scanner could not be initialized.')

        self._scanner.initialize_scan(use_filter=CM.config_dict[CF_FILTER_FINDINGS] is True)
        if not self._scanner.included_file_types:
            return Result(ResultCode.Error, 'No valid file types found to be scanned.')

        # In/Excluded file types and part paths (to be displayed in the log).
        CM.config_dict[CF_FILE_TYPES_INCLUDED] = list(self._scanner.included_file_types)
        CM.config_dict[CF_FILE_TYPES_EXCLUDED] = list(self._scanner.extension_excludes) or []
        CM.config_dict[CF_PATH_PARTS_EXCLUDED] = list(self._scanner.path_part_excludes) or []
        CM.config_dict[CF_SPECIFIED_SANE_IF_PATTERN_IN] = list(self._scanner.sane_if_pattern_in_lc_verbs) or []

        # Also add the specified excluded dirs and files
        extra_excludes = []
        if self._excluded_dir_names:
            extra_excludes = [d.strip() for d in self._excluded_dir_names.split(',')]
        if self._excluded_file_names:
            extra_excludes.extend([f.strip() for f in self._excluded_file_names.split(',')])
        for e in extra_excludes:
            if e not in CM.config_dict[CF_PATH_PARTS_EXCLUDED]:
                CM.config_dict[CF_PATH_PARTS_EXCLUDED].append(e)

        LA_manager.construct()  # not in init (unit test)
        LA_manager.set_languages(self._scanner.included_file_types)
        FW_manager.get_frameworks(self._scanner.included_file_types)
        return Result()

    def _validate_user_input(self):
        """ Validate input (except bool). None/empty is allowed. """
        try:
            validate_dir_name(f'{get_label(CF_INPUT_DIR)}', self._input_dir)
            validate_type(f'{get_label(CF_APPLICATION_TYPE)}', self._application_type, ApplicationTypeEnum)
            validate_value(f'{get_label(CF_LOG_TITLE)}', self._title, blank_allowed=True)
            validate_value(f'{get_label(CF_COMPANY_NAME)}', self._company_name)
            validate_value(f'{get_label(CF_CUSTOM_SEARCH_PATTERN)}', self._custom_pattern, blank_allowed=True)
            validate_attribute(f'{get_label(CF_OUTPUT_TYPE)}', self._output, LogType)
            validate_dir_name(f'{get_label(CF_OUTPUT_DIR)}', self._output_dir)
            validate_dir_name(f'{get_label(CF_DATA_DIR)}', self._data_dir)
            validate_value(f'{get_label(CF_PROJECT_NAME)}', self._project_name)
            validate_attribute(f'{get_label(CF_EXEC_TYPE)}', self._exec_type, ExecTypeEnum)
            if self._excluded_dir_names:
                [validate_dir_name(f'{get_label(CF_SPECIFIED_EXCLUDED_DIR_NAMES)}', i.strip())
                 for i in self._excluded_dir_names.split(',')]
            if self._excluded_file_names:
                [validate_value(f'{get_label(CF_SPECIFIED_EXCLUDED_FILE_NAMES)}', i.strip())
                 for i in self._excluded_file_names.split(',')]
            if self._sane_if_pattern_in:
                [validate_value(f'{get_label(CF_SPECIFIED_SANE_IF_PATTERN_IN)}', i.strip())
                 for i in self._sane_if_pattern_in.split(',')]
            validate_value(f'{get_label(CF_DEBUG_PATH)}', self._debug_path)
            validate_value(f'{get_label(CF_DEBUG_PATTERN_NAME)}', self._debug_pattern_name)
            validate_value(f'{get_label(CF_TIME_EXEC_MAX_S)}', self._time_exec_max_ms)
            validate_value(f'{get_label(CF_TIME_EXEC_LOG_THRESHOLD_MS)}', self._time_exec_threshold_ms)
        except ValueError as e:
            raise GeneralException(f'{e}')

    def _completion_messages(self, title, messages: [Message]):
        if not messages:
            return
        if messages:
            self._log_level = LogLevel.Verbose  # Always display header
            log.stripe()
            self._log(title, GREEN)
            [self._log(m.message) for m in messages]
            log.stripe()
            self._log_level = self._get_config_item(CF_LOG_LEVEL)  # Reset the _log level

    def _set_findings_manager(self):
        FM.initialize(FindingTemplate.FINDINGS, expected_file_count=self._scanner.total_files_with_findings)

    def _wrap_up(self) -> Result:
        result = Result()
        self._write_aggregated_findings()

        # Generate FindingsStatus.csv (incremental)
        if not self._one_pattern and self._has_db:
            """ FindingsStatus.csv via DB (incremental) """
            compare_level = CompareLevel.File if self._unit_test else CompareLevel.Dir
            result = self._findings_aggregated(self._session, compare_level)
            if result.code == ResultCode.Error:
                self._exit_program(result.text)
                return result

        # Remove all text files
        abs_path = os.path.abspath(CM.config_dict[CF_OUTPUT_DIR])
        if not self._unit_test and abs_path:
            for path, dirs, files in os.walk(os.path.abspath(CM.config_dict[CF_OUTPUT_DIR])):
                for filename in fnmatch.filter(files, "crisp*.txt"):
                    os.remove(os.path.join(path, filename))
        if abs_path:
            remove_empty_folders(abs_path)

        if self._error_message:
            result = Result(ResultCode.Error, self._error_message)
        else:
            self._log(f'{APP_NAME} {DONE}', GREEN)
        return result

    def _findings_aggregated(self, session, compare_level) -> Result:
        from src.db.BusinessLayer.DB.CrispDbc import CrispDbc
        return CrispDbc(
            input_path=FM.get_findings_path(),
            company_name=self._company_name,
            project_name=self._project_name,
            add_new_project=True,
            unit_test=self._unit_test,
            compare_level=compare_level,
            program_dir=self._input_dir,
            session=session,
        ).start(ETLAction.All)

    def _configure_session(self) -> Session:
        session = Session()
        if not self._title:
            self._title = self._company_name

        suffix = f'{self._title}_{self._project_name}' if self._project_name else self._title
        session.set_paths(
            self._unit_test, input_dir=self._input_dir, output_dir=self._output_dir, data_dir=self._data_dir,
            suffix=suffix, restart_session=True)
        session.company_name = self._company_name
        session.custom_pattern = self._custom_pattern
        session.debug_path = self._debug_path
        session.debug_pattern_name = self._debug_pattern_name

        self._companies = SP_manager.get_category_name_set(CATEGORY_COMPANY)
        self._companies.add('CRiSp_BV')  # Unit test
        return session

    def _configure_input(self) -> bool:

        CM.config_dict[CF_APPLICATION_TYPE] = self._application_type
        CM.config_dict[CF_EXEC_TYPE] = self._exec_type

        if not self._has_db:
            self._company_name = EMPTY
            self._project_name = EMPTY
            CM.config_dict[CF_INCREMENTAL_SCAN] = False
            CM.config_dict[CF_PROJECT_NAME] = EMPTY
            CM.config_dict[CF_CATEGORY_COMPANY] = EMPTY
        else:
            """ 
            Preparation: company and project name (for db-mode)
            """
            # -d = Incremental project scan via DB
            CM.config_dict[CF_INCREMENTAL_SCAN] = True
            # Override Default Configuration for:
            # -c  Company name
            result = self._get_list_item(
                self._company_name,
                CM.config_dict[CF_CATEGORY_COMPANY],
                CATEGORY_COMPANY,
                self._companies,
                default=self._company_name
            )
            # Get the key from the key-value item
            self._company_name = result.result_value

            # project name
            if self._input_dir and not self._project_name:
                self._project_name = findProject.find_project_name(self._input_dir, company_name=self._company_name)
            if not self._project_name:
                if self._get_config_item(CF_PROJECT_NAME):
                    self._project_name = self._get_config_item(CF_PROJECT_NAME)
            """ 
            Required parameters (in db-mode)
            """
            if not self._company_name:
                self._company_name = self._get_required_parm('company name', default=self._company_name)
            self._project_name = self._get_required_parm('project name', default=self._project_name)

        # Now company and project are determined.
        CM.config_dict[CF_PROJECT_NAME] = self._project_name
        CM.config_dict[CF_CATEGORY_COMPANY] = self._company_name

        # -p = One search pattern
        CM.config_dict[CF_CUSTOM_SEARCH_PATTERN] = self._custom_pattern \
            if self._custom_pattern and self._custom_pattern != SEARCH_DATA_PATH else EMPTY

        # -v = Verbose
        if self._verbose:
            CM.config_dict[CF_LOG_LEVEL] = LogLevel.Verbose
        else:
            CM.config_dict[CF_LOG_LEVEL] = LogLevel.Info

        # -a = All mode (no filtering)
        CM.config_dict[CF_FILTER_FINDINGS] = True if self._filter_mode else False

        # Sanitizers
        values = self._excluded_dir_names.split(',') if self._excluded_dir_names else []
        CM.config_dict[CF_SPECIFIED_EXCLUDED_DIR_NAMES] = [
            sanitize_text_to_alphanum_and_underscore(value, special_chars=",. $#*") for value in values]
        values = self._excluded_file_names.split(',') if self._excluded_file_names else []
        CM.config_dict[CF_SPECIFIED_EXCLUDED_FILE_NAMES] = [
            sanitize_text_to_alphanum_and_underscore(value, special_chars=",. $#*") for value in values]

        # debug filepath
        CM.config_dict[CF_DEBUG_PATH] = self._debug_path if self._debug_path else EMPTY
        CM.config_dict[CF_DEBUG_PATTERN_NAME] = self._debug_pattern_name if self._debug_pattern_name else EMPTY
        return True

    @staticmethod
    def _get_config_item(key):
        if key in CM.config_dict \
                and CM.config_dict[key] != NONE \
                and CM.config_dict[key] != EMPTY:
            return CM.config_dict[key]
        return None

    def _get_required_parm(self, name: str, default: str, part_of_file_name: bool = True) -> str:
        if not self._interactive:
            return default

        prefix = EMPTY
        while True:
            if not default:
                p = ui.ask(f'{prefix}Specify a valid {name} (q=quit): ')
            else:
                p = ui.ask(f"{prefix}Specify a valid {name}. Default='{default}' (q=quit): ")
            if p == QUIT:
                self._exit_program()
                return EMPTY
            if p == EMPTY:
                return default
            if part_of_file_name:
                if not isFilename(p):
                    prefix = f"'{p}' can not be part of a file name. "
                else:
                    return p

    def _get_list_item(self, input_key, config_key, item, item_list, default=None) -> Result:
        key = input_key
        if config_key == NONE:
            config_key = None
        # No input specified: use config value.
        if not input_key and type(config_key) != list:
            key = config_key
        res = check_item(item, key, item_list, default=default)
        if not res.code == ResultCode.Ok:
            self._exit_program(res.text)
            return res
        if not key:
            res.text = NONE
        return res

    @staticmethod
    def _get_interactive() -> bool:
        """ If input directory is EMPTY or has_db, then interactive processing """

        # if not self._input_dir or (self._has_db and not self._project_name):
        #     return True
        # else:
        #     return False
        return False

    def _get_user_input(self) -> bool:
        """
        Only in interactive mode, additionally get some input from the user
        """
        if self._input_dir:
            return True

        """ Title """
        if not self._title:
            self._title = ui.ask("Report title: ")
            if not isValidName(self._title, blank_allowed=True):
                self._exit_program()
                return False

        """ Input directory (must not contain output dir)"""
        output_dir = normalize_dir(CM.config_dict[CF_OUTPUT_DIR])
        self._input_dir = EMPTY
        while not os.path.exists(self._input_dir):
            self._input_dir = ui.ask("Input directory to scan recursively (c=current, q=quit): ")
            if self._input_dir == QUIT:
                self._exit_program()
                return False
            else:
                self._input_dir = validate_dir(self._input_dir,
                                               defaults_to_current=True,
                                               ask=True,
                                               create=False,
                                               compare_dir=output_dir)
                if self._input_dir == QUIT:
                    self._exit_program()
                    return False
        self._session.input_dir = self._input_dir

        """ CategoryCompanies (select from list) """
        if not self._company_name:
            dft = findCompany.find_company_name(self._input_dir, self._companies)
            if dft is None:
                dft = self._get_config_item(CF_CATEGORY_COMPANY)
            self._company_name = self._select_item_row(CATEGORY_COMPANY, dft, self._companies)

    def _start_log(self):
        """
        Start the logging
        """
        TimeManager.time_exec_max_s = self._time_exec_max_ms
        TimeManager.time_exec_threshold_ms = self._time_exec_threshold_ms

        if not os.path.isdir(self._session.log_dir):
            raise GeneralException(f"Log directory '{self._session.log_dir}' is not valid.")

        CM.config_dict[CF_OUTPUT_DIR] = self._session.output_dir
        CM.config_dict[CF_DATA_DIR] = self._session.data_dir
        CM.config_dict[CF_LOG_DIR] = self._session.log_dir

        log.start_log(CM.config_dict[CF_OUTPUT_TYPE], CM.config_dict[CF_LOG_LEVEL])
        self._log_level = LogLevel.Verbose
        self._log_started = True

        log.stripe()
        self._log("CRiSp - Code Review involving Search patterns", GREEN)
        log.stripe()
        self._log("Code base type . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(self._application_type.value)
        if self._has_db:
            self._log("Company  . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(self._company_name)
            self._log("Project  . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(self._project_name)
        self._log("Input directory to scan (recursively)  . . . : ", BLUE, new_line=False)
        self._log(findProject.sophisticate_path_name(self._input_dir))
        if self._custom_pattern and self._custom_pattern != SEARCH_DATA_PATH:
            self._log("Search pattern . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(CM.config_dict[CF_CUSTOM_SEARCH_PATTERN])
        self._log("Output directory . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(replace_root_in_path(CM.config_dict[CF_OUTPUT_DIR]))
        if self._has_db:
            self._log("Data directory . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(replace_root_in_path(CM.config_dict[CF_DATA_DIR]))

        self._log("Findings:", Color.BLUE)
        self._log("  Use filter . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_FILTER_FINDINGS])
        self._log("  Use business rules . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_APPLY_BUSINESS_RULES])
        self._log("  Quick scan . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_QUICK_SCAN])
        if CM.config_dict[CF_QUICK_SCAN] is True:
            self._log("   - without backtracking regex patterns", BLUE)
            if self._has_db and self._xref:
                self._log("   - without building XRef", BLUE)
        self._log("  Synchronize CVE  . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_SYNC_CVE])
        if self._has_db:
            self._log("Incremental project scan . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(CM.config_dict[CF_INCREMENTAL_SCAN])
        self._log("Execution type: Scan, dataflow, or both  . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_EXEC_TYPE].value)
        self._log("Logging:", Color.BLUE)
        self._log("  Level  . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_LOG_LEVEL].value)
        self._log("  Type . . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(CM.config_dict[CF_OUTPUT_TYPE].value)
        if self._output != LogType.Stdout:
            self._log("  Log directory  . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(replace_root_in_path(self._session.log_dir))
            self._log("  File . . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(log.log_file_name)
        self._log("  Pattern scan execution time threshold (ms) . . : ", BLUE, new_line=False)
        self._log(str(CM.config_dict[CF_TIME_EXEC_LOG_THRESHOLD_MS]))
        self._log("  Pattern scan execution time max (s)  . . . . . : ", BLUE, new_line=False)
        self._log(str(CM.config_dict[CF_TIME_EXEC_MAX_S]))
        if self._debug_path or self._debug_pattern_name:
            self._log("Debug:", Color.BLUE)
            self._log("  Path . . . . . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(self._debug_path)
            self._log("  Pattern name . . . . . . . . . . . . . . . : ", BLUE, new_line=False)
            self._log(self._debug_pattern_name)

        # File types
        log.stripe()
        self._log("  Languages found . . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(LA_manager.language_names) or BLANK)
        self._log("  Frameworks found  . . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(list(FW_manager.frameworks.keys())) or BLANK)
        self._log("  Included file types  . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(CM.config_dict[CF_FILE_TYPES_INCLUDED]) or BLANK)
        self._log("Sanitizers:", Color.BLUE)
        self._log("  Excluded file types  . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(CM.config_dict[CF_FILE_TYPES_EXCLUDED]) or BLANK)
        self._log("  Excluded path parts  . . . . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(CM.config_dict[CF_PATH_PARTS_EXCLUDED]) or BLANK)
        self._log("  Sane if pattern exists in  . . . . . . . . : ", BLUE, new_line=False)
        self._log(list_to_string(CM.config_dict[CF_SPECIFIED_SANE_IF_PATTERN_IN]) or BLANK)
        log.stripe()

        # Reset _log level
        self._log_level = self._get_config_item(CF_LOG_LEVEL)

    def _get_search_patterns(self):
        # A. custom pattern
        if self._custom_pattern and self._custom_pattern != SEARCH_DATA_PATH:
            # a. Specified as object in Unit-test, or
            # b. Try if it exists as string in the existing list
            search_patterns = [self._sp] if self._sp else SP_manager.get_valid_search_patterns(
                one_pattern_name=self._custom_pattern)
            # c.
            if not search_patterns:
                search_patterns = [SearchPattern(self._custom_pattern)]
        else:

            search_patterns = SP_manager.get_valid_search_patterns(
                application_type=self._application_type,
                languages=LA_manager.language_names,
                companies=[self._company_name]
            )

        if len(search_patterns) == 1:
            self._one_pattern = True

        return search_patterns

    def _scan(self) -> bool:
        """
        Search the base input directory with the search patterns
        """
        self._search_patterns = self._get_search_patterns()

        # Start progress bar
        log.start_progressbar('Searching', Color.GREEN, ceiling=len(self._search_patterns) - 1)
        okay = self._scan_patterns()
        log.stop_progressbar()
        return okay

    def _scan_patterns(self) -> bool:
        method = 'scan_patterns'
        header = self._get_config_item(CF_CUSTOM_SEARCH_PATTERN) is None
        quick_scan = self._get_config_item(CF_QUICK_SCAN)
        for sp in self._search_patterns:
            # Debug
            if self._debug_pattern_name and sp.pattern_name != self._debug_pattern_name:
                continue
            # Progress bar-1
            log.progress_increment()

            # Skip header
            if header:
                header = False
                continue

            # Skip long pattern names (like email regex) when quick_scan
            if quick_scan is True and len(sp.pattern) > MAX_PATTERN_LENGTH_AT_QUICK_SCAN:
                log.add_line(f'Search SKIPPED for {sp.category_name} {sp.category_value} {sp.pattern_name} - '
                             f'{str(self._scanner.total_pattern_findings)} findings')
                continue

            self._scan_pattern(self._scanner, sp, time_text=sp.pattern_name)

            if TimeManager.time_exec_error:
                log.add_line(f'{Color.RED}ERROR{Color.NC} - {method}: '
                             f"Scan of pattern '{sp.pattern_name}' took too long. "
                             f'Processing stopped. \n'
                             f'Possible solution: enlarge maximum execution time.')
                return False
        return True

    @time_exec
    def _scan_pattern(self, scanner, sp, time_text=EMPTY):
        # Example filename: basedir/Findings/action/crisp_categoryType_categoryName_searchPatternName.txt

        # Search pattern rows | Example:
        # ------------------------------
        # 0 = No                54
        # 1 = Category name     Language
        # 2 = Category value    Java
        # 3 = Pattern value     non-Crap
        # 4 = Pattern name      nonCrap
        # 5 = Action            Investigate
        # 6 = OutputFolderName  Investigate
        # 7 = OutputFileName    Language_Java_nonCrap

        write_empty_file = not CM.config_dict[CF_CLEANUP]

        scanner.apply_business_rules = False \
            if CM.config_dict[CF_APPLY_BUSINESS_RULES] is False else True

        scanner.scan_dir(sp, write_empty_file=write_empty_file)
        log.add_line(f'Searched {sp.category_name} {sp.category_value} {sp.pattern_name} - '
                     f'{str(scanner.total_pattern_findings)} findings', min_level=LogLevel.Info)

    def _write_aggregated_findings(self):
        """
        Create Findings.csv
        """
        self._log('Creating findings csv file...')
        # Reset (may be altered in external links plugin)
        self._set_findings_manager()
        # Append all .csv files in the result directory to Findings.csv.
        FM.aggregate_files()
        # 1-pattern mode: Print all formatted source lines and exit.
        if self._one_pattern:
            cols = FM.get_csv_column(FD.FI_Formatted_line)
            if cols:
                self._log_level = LogLevel.Verbose  # Always display header
                log.stripe()
                self._log('Occurrences of pattern: {}'.format(self._custom_pattern))
                log.stripe()
                self._log_level = self._get_config_item(CF_LOG_LEVEL)  # Reset the _log level
                for col in cols:
                    self._log(str(col))
            if not self._unit_test:
                return

    def _plugins(self):
        # Language/framework dependent plug-ins
        if self._has_db:
            from src.core.BusinessLayer.PluginManager import PluginManager
            plugin_manager = PluginManager(
                self._exec_type, LA_manager, FW_manager.frameworks, self._scanner, cli_mode=self._cli_mode)
            plugin_manager.run()

    def _write_scan_results(self):
        """
        Log the scan counters
        """
        self._log_level = LogLevel.Verbose
        log.new_line()

        log.stripe()
        self._log("  Total lines of code searched (LOC) . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.LOC))
        if len(self._search_patterns) == 1:
            self._log("  Pattern searched . . . . . . . . . . :  ", BLUE, new_line=False)
            self._log(self._custom_pattern)
        else:
            self._log("  Total patterns used  . . . . . . . . :  ", BLUE, new_line=False)
            self._log(str(len(self._search_patterns)))
        self._log("  Total files searched . . . . . . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.total_files_searched))
        self._log("  Total searches done  . . . . . . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.total_searches_done))
        self._log("  Total files with findings  . . . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.total_files_with_findings))
        self._log("  Total no. of patterns found  . . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.total_result_files_with_findings))
        self._log("  Total findings excluded by BRs . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.excluded_by_BRs))
        self._log("  Total remaining findings . . . . . . :  ", BLUE, new_line=False)
        self._log(str(self._scanner.total_findings))

        # Reset the _log level
        self._log_level = self._get_config_item(CF_LOG_LEVEL)

    def _select_item_row(self, class_name, dft, items):
        """
        Return the key of a selected key-value item
        :param class_name: Item list name
        :param dft: Default item
        :param items: Item list
        :return: key of the selected key-value item
        """
        question = "Filter on " + class_name
        result = select_item(class_name, dft, question, items)
        if result.code == ResultCode.Cancel:
            self._exit_program()
        return result

    def _log(self, line, color=EMPTY, new_line=True, error=False):
        # Log line
        log.add_coloured_line(line, color, new_line, self._log_level)
        # Remember last error
        if error:
            self._error_message = line

    def _exit_program(self, error_text=EMPTY):
        """
        Exit with logging a message
        :param error_text: message to _log
        """
        if error_text == EMPTY:
            error_text = 'Processing has been canceled by the user.'
        if self._log_started:
            self._log(errorText + error_text, error=True)
        raise GeneralException(error_text)
