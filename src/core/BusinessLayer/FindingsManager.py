# ---------------------------------------------------------------------------------------------------------------------
# FindingsManager.py
#
# Author      : Peter Heijligers
# Description : Consolidate all findings in a cross reference .csv file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-07 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import csv
import traceback

import src.core.Plugins.Const as ConstP
from src.core.DataLayer import FindingTemplate
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrorControl
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.core.DataLayer.CoreModel import CoreModel, FD as FD
from src.core.DataLayer.Finding import Finding
from src.gl.Functions import remove_color_code, path_leaf, get_int, find_files_for_type

from src.core.DataLayer.SearchPattern import SearchPattern
from src.gl.Const import APP_NAME, TXT_EXT, MAX_WRITES_PER_FILE, EMPTY, CSV_FINDINGS, MODEL_FINDINGS, FINDINGS, \
    CSV_EXT
from src.gl.Validate import enforce_valid_name, normalize_dir

PGM = 'FindingsManager'

# CRiSp summary figures
PAT_SCH = 'PatternSearched'
FILES_SCH = 'FilesSearched'
FILES_WITH_FINDINGS = 'FilesWithFindings'
PATS_FOUND = 'PatternsFoundInFindings'
EXT_LINKS = 'ExternalLinks'
TOTAL_FINDINGS = 'TotalFindings'

model = CoreModel()


class Singleton:
    """ Singleton """

    class FindingsManager(object):
        """
        Finding columns:
        0 = pattern
        1 = file_dir
        2 = file_name
        3 = line_no
        4 = index
        5 = line
        6 = pattern name
        7 = purpose
        8 = classification
        9 = severity
        10 = file_ext
        11 = formatted line
        """

        def __init__(self):
            self._template = EMPTY
            self._base_dir = EMPTY
            self._file_type = EMPTY
            self._total_files_to_search = 0
            self._findings = {}
            self._session = Session()

        def initialize(self, template, base_dir=None, file_type='txt', expected_file_count=0):
            self._template = template
            if base_dir:
                self._base_dir = base_dir
            elif template == FindingTemplate.FINDINGS:
                self._base_dir = self._get_findings_dir()
            else:
                self._base_dir = Session().log_dir

            # Header may be delivered directly or via a dictionary reference
            self._file_type = file_type
            self._total_files_to_search = expected_file_count
            self._findings[template] = []

        def add_finding(self, finding: Finding, template=FindingTemplate.FINDINGS):
            if template not in self._findings:
                self.initialize(template)
            self._findings[self._template].append(finding)

        def get_findings(self, template=FindingTemplate.FINDINGS) -> list:
            return self._findings.get(template) or []

        def get_findings_count(self, template=FindingTemplate.FINDINGS) -> int:
            return len(self._findings[template]) if template in self._findings else 0

        def _get_findings_dir(self):
            if not self._session.log_dir:
                return EMPTY
            return normalize_dir(f'{self._session.log_dir}{FINDINGS}', create=True)

        def get_findings_path(self):
            findings_dir = self._get_findings_dir()
            return f'{findings_dir}{CSV_FINDINGS}' if findings_dir else None

        def write_findings(self, sp: SearchPattern, number_found: int = 0, base=None) -> bool:
            """
            Write the findings found (e.g. to a raw .txt file in csv format)
            param: base is for unit test only
            """
            number_found = self.get_findings_count() if number_found == 0 else number_found
            if number_found == 0:
                return True

            dir_name = base if base else self._get_findings_dir()
            pattern_name = sp.pattern_name or sp.pattern
            pattern_name = enforce_valid_name(pattern_name).lower()
            data_path = f'{dir_name}{APP_NAME.lower()}_{sp.category_name.lower()}_' \
                        f'{sp.category_value.lower()}_{pattern_name}_{str(number_found)}{TXT_EXT}'
            first = True
            try:
                with open(data_path, 'w') as csvFile:
                    csv_writer = csv.writer(
                        csvFile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
                    for F in self._findings[self._template]:
                        if first:
                            first = False
                            csv_writer.writerow(FindingTemplate.template_headers[FindingTemplate.FINDINGS])
                        csv_writer.writerow(
                            [sp.pattern,
                             sp.category_name,
                             sp.category_value,
                             sp.status,
                             F.truncated_dir,
                             F.file_name,
                             str(F.line_no),
                             str(F.start_pos),
                             F.line,
                             sp.pattern_name,
                             sp.purpose,
                             sp.classification,
                             sp.OWASP,
                             sp.severity,
                             F.file_ext,
                             F.formatted_line]
                        )
                return True
            except IOError:
                ErrorControl().add_line('ERROR', traceback.format_exc())
                return False

        def aggregate_files(self, data_path=None):
            """
            Get all findings.txt working files in result directory (recursively)
            and append them to the Findings.csv summary file.
            """
            if not data_path:
                data_path = self.get_findings_path()

            try:
                with open(data_path, 'w') as outFile:
                    header_printed = False
                    log_file_name = str(Log().log_file_name)
                    """ 
                    Walk through the (log output) directory.
                    The content of all files (all findings) are added to the output file.
                    """
                    i = 0
                    for filePath in find_files_for_type("*." + self._file_type, self._base_dir):
                        # Skip the result directory (incl. the Log and FindingsManager file created here!)
                        # to prevent looping.
                        # filePath.endswith(output_path[1:]) or \
                        if filePath.endswith(log_file_name) or \
                                filePath.endswith(CSV_FINDINGS) or \
                                filePath.endswith('.DS_Store'):
                            continue
                        i += 1
                        if i > MAX_WRITES_PER_FILE:
                            self.max_error(filePath)
                            return
                        if i > (self._total_files_to_search / 10):
                            i = 0
                        fo = open(filePath, 'r')
                        # a. First line
                        # Read the first line (should be header row) from the file
                        line = fo.readline()
                        # (Not a header ?! First lines may be excel rubbish...)
                        isheader = False
                        while line != EMPTY and not isheader:
                            # Skip header (except the very 1st time)
                            if line.startswith(FindingTemplate.template_headers.get(self._template)[0]):
                                isheader = True
                                if not header_printed:
                                    outFile.write(line.rstrip() + '\r')
                                    header_printed = True
                            line = fo.readline()

                        # No header found: exit.
                        if line == EMPTY:
                            ErrorControl().add_line('ERROR', 'No header found. File "' + filePath + '" not processed.')
                        # b. Print until EOF
                        else:
                            j = 0
                            while line != EMPTY:
                                j += 1
                                if j > MAX_WRITES_PER_FILE:
                                    self.max_error(filePath)
                                    return
                                outFile.write(line.rstrip() + '\r')
                                line = fo.readline()

                        # Close the files
                        fo.close()
            except IOError:
                ErrorControl().add_line('ERROR', traceback.format_exc())

        def get_csv_column(self, col_name):
            """
            Purpose: In case of 1 pattern, the formatted_source_lines must be printed.
            """

            csv_manager = CsvManager()
            col_no = model.get_zero_based_column_number(MODEL_FINDINGS, col_name)

            col = csv_manager.get_column(col_no, data_path=self.get_findings_path())
            return col

        @staticmethod
        def max_error(path):
            ErrorControl().add_line('ERROR', f'{PGM}: Max. no of writes ({str(MAX_WRITES_PER_FILE)})'
                                             f' has been reached. File path: {path}')

        @staticmethod
        def write_results(input_items, csv_type, data_path, base_dir=None):
            if not input_items:
                return
            rows = []
            for row in input_items:
                if csv_type == FindingTemplate.REDOS:
                    rows.append([
                        row.file_name,
                        row.line_no,
                        row.start_pos,
                        row.end_pos,
                        row.extract_raw_finding(),
                        row.dir_name])
                elif csv_type == FindingTemplate.MODEL_FIELD_VALIDATIONS:
                    dir_name, file_name = path_leaf(row.element.path)
                    dir_name = dir_name.replace(base_dir, EMPTY) if base_dir else None
                    rows.append([
                        row.context_type,
                        row.title,
                        row.parent_name,
                        row.used_for_input,
                        row.vulnerable,
                        row.element.line_no,
                        dir_name,
                        file_name,
                        row.element.name,
                        row.field_type,
                        row.contains_id,
                        row.length,
                        row.element.line,
                    ])
                elif csv_type == FindingTemplate.MODEL_WARNINGS:
                    message = remove_color_code(row.message)
                    rows.append([message])
                elif csv_type == FindingTemplate.ENDPOINTS:
                    rows.append(row)
                elif csv_type == FindingTemplate.REST_FRAMEWORK_ENDPOINTS_DATA_FLOW:
                    rows.append([
                        row[ConstP.TITLE],
                        row[ConstP.CLASS_NAME],
                        row[ConstP.METHOD_NAME],
                        row[ConstP.PARAMETER_NAME],
                        row[ConstP.PASSED_TO_METHODS],
                        row[ConstP.RETURNED_IN],
                        row[FD.FI_Line_no],
                        row[FD.FI_File_dir],
                        row[FD.FI_File_name],
                    ])
            CsvManager().write_rows(
                rows, FindingTemplate.template_headers[csv_type], open_mode='a', data_path=data_path, add_id=False)

        @staticmethod
        def get_paths(findings: [Finding]) -> set:
            return set(f.path for f in findings)

        def get_result_figures(self):
            """
            :return: Figures in CRiSp log summary
            """
            totals_dict = {PAT_SCH: EMPTY}
            str_pos = 43
            end_pos = str_pos + 6

            # Read whole Log file
            f = open(self._base_dir, mode='r')
            lines = f.readlines()
            f.close()

            # Read figures only
            for line in lines:
                if str(line).startswith('  Pattern searched'):
                    totals_dict[PAT_SCH] = line[str_pos:end_pos].rstrip()
                elif str(line).startswith('  Total files searched'):
                    totals_dict[FILES_SCH] = get_int(line[str_pos:end_pos].rstrip())
                elif str(line).startswith('  Total files with findings'):
                    totals_dict[FILES_WITH_FINDINGS] = get_int(line[str_pos:end_pos].rstrip())
                elif str(line).startswith('  Total no. of patterns found'):
                    totals_dict[PATS_FOUND] = get_int(line[str_pos:end_pos].rstrip())
                elif str(line).startswith('  Total remaining findings'):
                    totals_dict[TOTAL_FINDINGS] = get_int(line[str_pos:end_pos].rstrip())

            # external links
            ext_links_path = f'{Session().log_dir}external_links_{Session().log_dir_name}{CSV_EXT}'
            totals_dict[EXT_LINKS] = CsvManager().len(ext_links_path)

            return totals_dict

    # storage for the instance reference
    __instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if Singleton.__instance is None:
            # Create and remember instance
            Singleton.__instance = Singleton.FindingsManager()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton__instance'] = Singleton.__instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self.__instance, attr, value)
