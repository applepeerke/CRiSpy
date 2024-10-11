import os
import unittest

from src.core.BusinessLayer.CRiSpy import CRiSpy as crisp
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Functions.Functions import get_root_dir
from src.gl.BusinessLayer.CsvManager import CsvManager as Data_Manager
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session

EMPTY = ''

PAT_SCH = 'PatternSearched'
FILES_SCH = 'FilesSearched'
FILES_WITH_FINDINGS = 'FilesWithFindings'
PATS_FOUND = 'PatternsFoundInFindings'
EXT_LINKS = 'ExternalLinks'
TOTAL_FINDINGS = 'TotalFindings'

data_manager = Data_Manager()
search_pattern_manager = SearchPattern_Manager()
root_dir = get_root_dir()
pattern_searched = EMPTY


def get_input_dir():
    return f'{root_dir}UT/Project_comment/src'


class CrispTestCase(unittest.TestCase):

    def test_TC01_Exclude_comment(self):
        title = "_TC01_Exclude_comment"
        prediction = {
            FILES_SCH: 6,
            FILES_WITH_FINDINGS: 0,
            PATS_FOUND: 0,
            TOTAL_FINDINGS: 0
        }
        self.start_crisp(title=title, include_comment=False)
        self.evaluate_crisp(prediction)

    def test_TC02_Include_comment(self):
        title = "_TC02_Include_comment"
        prediction = {
            FILES_SCH: 6,
            FILES_WITH_FINDINGS: 6,
            PATS_FOUND: 1,
            TOTAL_FINDINGS: 19
        }
        self.start_crisp(title=title, include_comment=True)
        self.evaluate_crisp(prediction)

    def evaluate_crisp(self, prediction):
        log_path = Log().log_path
        self.assertEqual(os.path.exists(log_path), 1, 'Log path "' + log_path + '" does not exist.')

        totals_dict = self.get_result_figures(log_path)
        self.assertEqual(len(totals_dict), 4, 'Totals are not complete.')
        self.assertEqual(self.is_prediction_correct(prediction, totals_dict), True, 'Prediction is not correct')

    @staticmethod
    def start_crisp(title, include_comment):
        # Configure Session
        Session().set_paths(unit_test=True, suffix=title)
        input_dir = get_input_dir()
        Session().input_dir = input_dir
        sp = SearchPattern(pattern='md5', include_comment=include_comment, apply_business_rules=False)

        # Start CRiSp
        crispy = crisp(
            input_dir=input_dir,
            log_title=title,
            custom_search_pattern=sp
        )
        crispy.start(unit_test=True)

    def get_result_figures(self, log_path):
        global pattern_searched
        totals_dict = {}
        str_pos = 40
        end_pos = str_pos + 6

        # Read whole Log file
        f = open(log_path, mode='r')
        lines = f.readlines()
        f.close()

        pattern_searched = EMPTY

        # Read figures only
        for line in lines:
            if str(line).startswith('  Pattern searched'):
                pattern_searched = line[str_pos:end_pos].strip()
            elif str(line).startswith('  Total files searched'):
                totals_dict[FILES_SCH] = self.get_int(line[str_pos:end_pos].rstrip())
            elif str(line).startswith('  Total files with findings'):
                totals_dict[FILES_WITH_FINDINGS] = self.get_int(line[str_pos:end_pos].rstrip())
            elif str(line).startswith('  Total no. of patterns found'):
                totals_dict[PATS_FOUND] = self.get_int(line[str_pos:end_pos].rstrip())
            elif str(line).startswith('  Total remaining findings'):
                totals_dict[TOTAL_FINDINGS] = self.get_int(line[str_pos:end_pos].rstrip())

        return totals_dict

    def is_prediction_correct(self, prediction, totals_dict):
        self.assertEqual(pattern_searched, 'md5')
        self.assertEqual(totals_dict[FILES_SCH], prediction[FILES_SCH],
                         str(prediction[FILES_SCH]) + ' expected, ' +
                         str(totals_dict[FILES_SCH]) + ' found.')
        self.assertEqual(totals_dict[FILES_WITH_FINDINGS], prediction[FILES_WITH_FINDINGS],
                         str(prediction[FILES_WITH_FINDINGS]) + ' expected, ' +
                         str(totals_dict[FILES_WITH_FINDINGS]) + ' found.')
        self.assertEqual(totals_dict[PATS_FOUND], prediction[PATS_FOUND],
                         str(prediction[PATS_FOUND]) + ' expected, ' +
                         str(totals_dict[PATS_FOUND]) + ' found.')
        self.assertEqual(totals_dict[TOTAL_FINDINGS], prediction[TOTAL_FINDINGS],
                         str(prediction[TOTAL_FINDINGS]) + ' expected, ' +
                         str(totals_dict[TOTAL_FINDINGS]) + ' found.')
        return True

    @staticmethod
    def get_int(value):
        if value == EMPTY:
            return 0
        try:
            return int(value)
        except ValueError:
            return -1


if __name__ == '__main__':
    unittest.main()
