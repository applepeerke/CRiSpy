# ---------------------------------------------------------------------------------------------------------------------
# Scanner.py
#
# Author      : Peter Heijligers
# Description : Find a string in specified file type in a base directory
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import fnmatch
import os
import re

from root_functions import ROOT_DIR
from src.core.BusinessLayer.BusinessRuleManager import BusinessRuleManager
from src.core.BusinessLayer.CommentManager import CommentManager
from src.core.BusinessLayer.ComplexFunctions import ComplexFunctions
from src.core.BusinessLayer.FilterManager import FilterManager
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.Finding import Finding
from src.core.DataLayer.SearchPattern import SearchPattern
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.Const import MAX_READS_PER_FILE, EMPTY, SEARCH_ONLY_FOR_ASSIGNED_TO, BLANK, APP_FIELD_LIMIT
from src.gl.Enums import Output
from src.gl.Functions import strip_bytes_and_crlf
from src.gl.GeneralException import GeneralException

PGM = 'Scanner'

FilterM = FilterManager()
FM = Findings_Manager()
BM = BusinessRuleManager()
CM = CommentManager()
CF = ComplexFunctions()


class Scanner(object):

    @property
    def base_dir(self):
        return self._base_dir

    @property
    def file_type(self):
        return self._file_type

    @property
    def scanned_paths(self):
        return self._scanned_paths

    @property
    def total_findings(self):
        return self._total_findings

    @property
    def total_pattern_findings(self):
        return self._total_pattern_findings

    @property
    def total_searches_done(self):
        return self._total_searches_done

    @property
    def total_files_searched(self):
        return self._total_files_searched

    @property
    def total_files_with_findings(self):
        return self._total_files_with_findings

    @property
    def total_result_files_with_findings(self):
        return self._total_result_files_with_findings

    @property
    def total_findings_for_this_source(self):
        return self._total_findings_for_this_source

    @property
    def apply_business_rules(self):
        return self._apply_business_rules

    @property
    def included_file_types(self):
        return self._included_file_types

    @property
    def extension_excludes(self):
        return self._extension_excludes

    @property
    def path_part_excludes(self):
        return self._path_part_excludes

    @property
    def sane_if_pattern_in_lc_verbs(self):
        return self._sane_if_pattern_in_lc_verbs

    @property
    def excluded_by_BRs(self):
        return self._excluded_by_BRs

    @property
    def LOC(self):
        return self._LOC

    @property
    def findings(self):
        return FM.get_findings(self._template)

    """
    Setters
    """

    @file_type.setter
    def file_type(self, value):
        self._file_type = value

    @apply_business_rules.setter
    def apply_business_rules(self, value):
        self._apply_business_rules = value

    @total_findings.setter
    def total_findings(self, value):
        self._total_findings = value

    """
    Find a string in specified file types in a base directory (specify file_type without ".")
    """
    file_found = 0

    def __init__(self, base_dir=None, file_type='*', db=None, quick_scan=False,
                 finding_template=FindingTemplate.FINDINGS, debug_path=None):
        self._base_dir = base_dir
        self._file_type = file_type
        self._db = db
        self._quick_scan = quick_scan
        self._template = finding_template

        FilterM.debug_path = debug_path  # Single file path in DEBUG mode

        self._scanned_paths = []
        self._included_file_types = set()
        self._extension_excludes = set()
        self._path_part_excludes = set()
        self._sane_if_pattern_in_lc_verbs = set()

        self._total_findings = 0
        self._total_pattern_findings = 0
        self._total_searches_done = 0
        self._total_files_searched = 0
        self._total_files_with_findings = 0
        self._total_result_files_with_findings = 0
        self._total_findings_for_this_source = 0
        self._use_filter = False
        self._filters = None
        self._file_path = None
        self._file_path_dict = {}
        self._apply_business_rules = True
        self._excluded_by_BRs = 0
        self.lin = EMPTY
        FM.initialize(self._template)
        self._LOC = 0
        self._blacklist = []

    def initialize_scan(self, use_filter=True):
        FM.initialize(self._template)
        self._use_filter = use_filter
        if use_filter:
            FilterM.set_filter()
        """
        Construct and return file types set from base_dir
        :return: List of file types.
        """
        for file_path in self.find_files("*.*", self._base_dir):
            _, file_extension = os.path.splitext(file_path)
            if file_extension != EMPTY:
                self._included_file_types.add(file_extension)

        self._extension_excludes = FilterM.extension_excludes
        self._path_part_excludes = FilterM.path_part_excludes
        self._sane_if_pattern_in_lc_verbs = FilterM.sane_if_pattern_in_verb

    def scan(self, sp=None, ):
        self._scanned_paths = []
        self._total_files_searched = 0
        for path in self.find_files(f'*.{self._file_type}', self._base_dir):
            """ Scan a source file """
            basename = os.path.basename(path)
            if basename not in ['.DS_Store']:
                self._scanned_paths.append(path)
                if sp:
                    self.scan_source(path, sp)
                    self._total_files_searched += 1
                    self._total_searches_done += 1

    def scan_dir(self, sp: SearchPattern, output=Output.File, write_empty_file=True, base=None) -> bool:
        """
        Scan a directory for a search pattern (recursively)
        :param output: type of output [File, Object]
        :param sp: SearchPattern instance
        :param write_empty_file:
        :param base: Only for Unit test
        """

        """ Scan a directory for a search pattern (recursively) """
        FM.initialize(self._template)
        self._LOC = 0
        self._total_findings_for_this_source = 0
        # Scan
        self.scan(sp)

        """
        Counters
        """
        self._total_pattern_findings = len(FM.get_findings(self._template))
        if self._total_pattern_findings > 0:
            self._total_findings += self._total_pattern_findings
            self._total_result_files_with_findings += 1
            self._total_files_with_findings = len(self._file_path_dict)
        """
        Output
        """
        # Write findings
        if output == Output.File and (self._total_pattern_findings > 0 or write_empty_file):
            FM.write_findings(sp, self._total_pattern_findings, base=base)

        return self._total_pattern_findings > 0

    def scan_dir_to_findings(self, search_pattern: SearchPattern, input_dir=None, file_type=None) -> [Finding]:
        """
        Scan a directory for a search pattern (recursively) to return a list of Findings
        """
        FM.initialize(self._template)

        scan_dir = input_dir or self._base_dir
        file_type = file_type or self._file_type
        file_paths = self.dir_to_valid_list(file_type, scan_dir)
        for path in file_paths:
            self.scan_source(path, search_pattern)
        return FM.get_findings(self._template)

    def dir_to_valid_list(self, file_type, base_dir) -> set:
        valid_paths = set()
        for file_path in self.find_files(f'*.{file_type}', base_dir):
            if os.path.basename(file_path) not in ['.DS_Store']:
                valid_paths.add(file_path)
        self._extension_excludes = FilterM.extension_excludes
        self._path_part_excludes = FilterM.path_part_excludes
        self._sane_if_pattern_in_lc_verbs = FilterM.sane_if_pattern_in_verb
        return valid_paths

    def find_files(self, file_type, basedir=os.curdir):
        """
        Return all file paths matching the specified file type in the specified base directory (recursively).
        """
        if not basedir.startswith(ROOT_DIR):
            raise GeneralException('Directory name is not within the root directory.')
        for path, dirs, files in os.walk(os.path.abspath(basedir)):
            if FilterM.is_valid_dir(basedir, path, self._use_filter):
                for filename in fnmatch.filter(files, file_type):
                    if FilterM.is_valid_filename(filename, self._use_filter):
                        yield os.path.join(path, filename)

    def scan_line(
            self, sp: SearchPattern, file_name=EMPTY, file_ext=EMPTY, line=EMPTY, apply_BRs=True, line_no=0,
            path=None) -> int:
        return self.get_index(sp, file_name, file_ext, line, self._use_filter, apply_BRs, line_no=line_no, path=path)

    def scan_source(self, path, sp: SearchPattern):
        if path in self._blacklist:
            return

        self._file_path = path
        """
        Scan a source for a search value
        :param sp: search_pattern
        :param file_path: absolute path to the file
        :returns: appends rows to findings list
        """
        self._total_findings_for_this_source = 0

        basename = os.path.basename(path)
        file_name, file_ext = os.path.splitext(basename)
        CM.initialize_file(file_ext)

        # User-specified flag overrules search-pattern flag
        apply_BRs = sp.apply_business_rules if self._apply_business_rules else False
        line_no = 0

        # Open file for reading
        try:
            fo = open(path, 'rb')

            # Read the first line from the file, convert binary to string (utf-8)
            line = str(fo.readline())

            # Initialize counter for line number
            line_no = 1
            # Loop until EOF
            while line != 'b\'\'' and line_no < MAX_READS_PER_FILE:
                # Not in Comment block
                if sp.include_comment or not CM.is_comment(line):
                    index = self.scan_line(sp, file_name, file_ext, line, apply_BRs, line_no=line_no)
                    """
                    Pattern found
                    """
                    if index != -1:
                        FM.add_finding(
                            Finding(
                                path=self._file_path,
                                line_no=line_no,
                                line=self.lin,
                                start_pos=index,
                                base_dir=self.base_dir,
                                search_pattern=sp
                            )
                        )
                        self._total_findings_for_this_source += 1
                        # Count no. of matches in every code base file
                        if self._file_path not in self._file_path_dict:
                            self._file_path_dict[self._file_path] = 1
                        else:
                            self._file_path_dict[self._file_path] += 1

                # Read next line
                line = str(fo.readline())
                # Increment line counter
                line_no += 1
                if line_no == MAX_READS_PER_FILE:
                    Log().add_line(f"File blacklisted. Max. reads ({MAX_READS_PER_FILE}) reached in file '{basename}'")
                    self._blacklist.append(self._file_path)
            # Close the file
            fo.close()
            # LOC
            self._LOC = self._LOC + line_no - 1
        except (IOError, IndexError, Exception) as e:
            text = e.args[1] if e.args and len(e.args) > 1 else e.args[0]
            Log().add_line(f"File blacklisted. Error occurred at line no {line_no}: '{text}' in {file_name}. "
                           f"Pattern name was '{sp.pattern_name}'. Path is '{self._file_path}'")
            self._blacklist.append(self._file_path)

    def get_index(self, sp, file_name, file_ext, line, use_filter=True, apply_BR=True, convert=True, line_no=0,
                  path=None) -> int:
        # Skip long lines without spaces (like base64 encoding), e.g.
        # //# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uI.....==
        if len(line) > 10000 and line.count(" ") < 2:
            return -1

        """
        Search for string in line
        """
        line_lc, pattern_lc = EMPTY, EMPTY

        # a. Regex
        if str(sp.pattern).startswith('r"'):
            index = regex(line, sp.pattern[2:len(sp.pattern) - 1])  # Skip the "r" and trailing ""
        # b. Complex get_index
        elif str(sp.pattern).startswith('*CF'):
            path = self._file_path or path
            index = CF.get_index(
                strip_bytes_and_crlf(line), sp.pattern, file_name, file_ext, line_no, path)
        # c. Find
        else:
            line_lc = line.lower()
            pattern_lc = sp.pattern.lower()
            index = line_lc.find(pattern_lc)

        if index == -1:
            return -1

        """
        Pattern found!
        """
        # Constraint-1: Not found if: pattern in the line is part of user-specified project-specific sane pattern(s).
        if self._sane_if_pattern_in_lc_verbs \
                and any(verb in line_lc and pattern_lc in verb for verb in self._sane_if_pattern_in_lc_verbs):
            return -1
        # Constraint-2: If Pattern must be target of an assignment...
        if sp.search_only_for == SEARCH_ONLY_FOR_ASSIGNED_TO:
            index_as = line.find('=')
            if index_as > 0 and line[index_as - 1] in ('-', '+'):  # Avoid -= and +=
                return -1
            index_as = line.find(':') if index_as == -1 else index_as  # Ruby: "password:"
            # ... and target after '='
            if index_as < index:
                return -1

        # Optional conversion
        if not convert:
            self.lin = line
        else:
            # Replace TAB by BLANK
            if '\\t' in line:
                # Correct index for no. of tabs before index
                for i in range(0, index):
                    if i + 2 < len(line) and line[i:i + 2] == '\\t':
                        index -= 1
                line = line.replace('\\t', BLANK)
            self.lin = line[2:len(line) - 1]

            index -= 2 if index >= 2 else 0  # Correct find_file position, after regex 0 may be returned.
            if index < 0:
                print(f'index < 0: line={line}, pattern={sp.pattern_name}')
            if self.lin.endswith('\\n'):
                self.lin = self.lin[:-2]
            if self.lin.endswith('\\r'):
                self.lin = self.lin[:-2]

        # CSV field limit ca. 131000, Excel field limit ca. 32000, 1000 is enough.
        if len(self.lin) > APP_FIELD_LIMIT:
            if APP_FIELD_LIMIT < index:
                self.lin = f'...{self.lin[index:]}'
            if len(self.lin) > APP_FIELD_LIMIT:
                self.lin = f'{self.lin[:APP_FIELD_LIMIT]}...'

        """
        Apply filter
        """
        if use_filter:
            # a. Filter on comment
            if not sp.include_comment and CM.is_inline_comment(self.lin, index):
                return -1
            # b. Filter on "starts with"
            elif FilterM.ignore_source_lines_start:
                t_line = self.lin.lstrip()
                for start in FilterM.ignore_source_lines_start:
                    if t_line.startswith(start):
                        return -1

        """
        Apply BRs
        """
        excluded = False
        if apply_BR:
            excluded = BM.exclude(self.lin, sp.pattern_name, index, file_ext=file_ext, file_name=file_name)
        if excluded:
            self._excluded_by_BRs += 1
            return -1

        """
        Pattern is valid!
        """
        return index

    @staticmethod
    def _strip(line):
        # Remove byte presentation
        if line[0:2] == "b\'":
            line = line[2:len(line) - 1]
        # Remove CRLF
        if line.endswith('\\n'):
            line = line[:len(line) - 2]
        if line.endswith('\\r'):
            line = line[:len(line) - 2]
        return line


def regex(line, sp):
    result = re.search(sp, line, re.IGNORECASE)
    if result:
        s = result.start()
        if s is None:
            return 0
        return s
    return -1
