import unittest

import src.core.BusinessLayer.CRiSpy
from src.core.BusinessLayer.FindingsManager import PAT_SCH, FILES_SCH, FILES_WITH_FINDINGS, PATS_FOUND, \
    TOTAL_FINDINGS, EXT_LINKS
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.core.DataLayer import FindingTemplate
from root_functions import get_root_dir
from src.gl.BusinessLayer.CsvManager import CsvManager as Data_Manager
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import CATEGORY_COMPANY, SEARCH_DATA_PATH
from src.gl.Enums import ExecTypeEnum
from src.gl.Validate import *

EMPTY = ''

FM = Findings_Manager()
data_manager = Data_Manager()
search_pattern_manager = SearchPattern_Manager()
root_dir = get_root_dir()

pattern_searched = EMPTY


def get_input_dir():
    return f'{root_dir}UT/Project/src'


class SearchPatternTestCase(unittest.TestCase):
    # Test parameters
    # -c = Companies
    def test_companies_in_patterns_list(self):
        self.assertGreater(len(search_pattern_manager.get_category_name_set(CATEGORY_COMPANY)), 0)

    # "/crisp/" must exist in the current path
    def test_crisp_in_current_dir(self):
        self.assertTrue(root_dir)

    # Unit test project must exist in the current path
    def test_unittest_present_in_current_dir(self):
        self.assertEqual(os.path.exists(get_input_dir()), 1, 'Input dir "' + get_input_dir() + '" does not exist.')


class CrispTestCase(unittest.TestCase):
    def test_TC00_remove_config_file(self):
        config_path = Session().base_dir + 'app.config'
        if os.path.isfile(config_path):
            os.remove(config_path)
            self.assertFalse(os.path.isfile(config_path))

    # C R I S P
    # See the excel decision table "CRiSp Testmatrix.xlsx" to calculate the predictions for all test cases!
    # This works as on 2017-12-07
    # The Log file total counts are compared with the prediction.

    def test_TC01(self):
        # TC01 = No companies and No languages
        title = "_TC01_General"
        prediction = {
            PAT_SCH: EMPTY,
            FILES_SCH: 26,
            FILES_WITH_FINDINGS: 15,
            PATS_FOUND: 2,
            EXT_LINKS: 15,
            TOTAL_FINDINGS: 30
        }
        self.start_crisp(title=title)
        self.evaluate_crisp(prediction)

    def test_TC04(self):
        # TC04 Specify Title, company and framework_name
        title = "_TC04_CF"
        prediction = {
            PAT_SCH: EMPTY,
            FILES_SCH: 26,
            FILES_WITH_FINDINGS: 15,
            PATS_FOUND: 2,
            EXT_LINKS: 15,
            TOTAL_FINDINGS: 30
        }
        self.start_crisp(title=title, company="KPN")
        self.evaluate_crisp(prediction)

    def test_TC09(self):
        # TC05 = Specify a pattern
        title = "_TC09_Pattern"
        prediction = {
            PAT_SCH: 'hello',
            FILES_SCH: 26,
            FILES_WITH_FINDINGS: 10,
            PATS_FOUND: 1,
            EXT_LINKS: 0,
            TOTAL_FINDINGS: 10
        }
        self.start_crisp(title=title, company="KPN", custom_pattern="hello")
        self.evaluate_crisp(prediction)

    def test_TC25(self):
        # TC16 = Filter paths and extensions
        title = "_TC25_Filtered"
        prediction = {
            PAT_SCH: 'hello',
            FILES_SCH: 10,
            FILES_WITH_FINDINGS: 5,
            PATS_FOUND: 1,
            EXT_LINKS: 0,
            TOTAL_FINDINGS: 5
        }
        self.start_crisp(title=title, company="KPN", custom_pattern="hello", filter_mode=True)
        self.evaluate_crisp(prediction)

    def evaluate_crisp(self, prediction):
        global pattern_searched
        log_path = Log().log_path
        self.assertEqual(os.path.exists(log_path), 1, 'Log path "' + log_path + '" does not exist.')
        FM.initialize(FindingTemplate.FINDINGS, log_path)
        totals_dict = FM.get_result_figures()
        self.assertEqual(len(totals_dict), 6, 'Totals are not complete.')
        self.assertEqual(self.is_prediction_correct(prediction, totals_dict), True, 'Prediction is not correct')

    @staticmethod
    def start_crisp(title=EMPTY,
                    company=EMPTY,
                    custom_pattern=SEARCH_DATA_PATH,
                    verbose=False,
                    filter_mode=False,
                    exec_type=ExecTypeEnum.Scan):
        # Configure Session
        Session().set_paths(unit_test=True, suffix=title)
        Session().input_dir = f'{root_dir}UT/Project/src'

        # Start CRiSp
        crispy = src.core.BusinessLayer.CRiSpy.CRiSpy(
            input_dir=get_input_dir(),
            log_title=title,
            company_name=company,
            custom_search_pattern=custom_pattern,
            verbose=verbose,
            filter_findings=filter_mode,
            exec_type=exec_type
        )
        crispy.start(unit_test=True)

    def is_prediction_correct(self, prediction, totals_dict):
        if prediction[PAT_SCH]:
            self.assertEqual(prediction[PAT_SCH], 'hello')
        else:
            self.assertEqual(pattern_searched, EMPTY)
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


if __name__ == '__main__':
    unittest.main()
