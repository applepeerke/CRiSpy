import os
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.BusinessRuleManager import BusinessRuleManager
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.core.DataLayer.SearchPattern import SearchPattern

session = Session()
search_manager = SearchPattern_Manager()

session.set_paths(unit_test=True)
current_dir = os.path.dirname(os.path.realpath(__file__))

# Directories
input_dir = session.design_dir
source_file_path1 = input_dir + 'UT_BR_patterns.txt'
source_file_path2 = input_dir + 'Web.config'
source_file_path3 = input_dir + 'UT_BR_patterns.tag'
source_file_path4 = input_dir + 'UT_BR_patterns.jsp'
scanner = Scanner.Scanner(input_dir, file_type='*')
# Just use some sample patterns and compare with file "UT_BR_Patterns.txt"
predictions = {}


def _add_sp(pattern, pattern_name=None, output_path=None, prediction_with_BR=0, prediction_without_BR=0):
    pattern_name = pattern_name or pattern
    predictions[pattern_name] = [
        SearchPattern(pattern=pattern, pattern_name=pattern_name, output_subfolder_name=output_path),
        prediction_with_BR,
        prediction_without_BR
    ]


_add_sp(pattern='script', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=3)
_add_sp(pattern='lock', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=3)
_add_sp(pattern='execute', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=2)
_add_sp(pattern='hash', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=5)
_add_sp(pattern='salt', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=2)
_add_sp(pattern='todo', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=2)
_add_sp(pattern='r"^(?!.*(soap|xmlns|namespace|www.w3.org)).*(http://)"', pattern_name='http',
        output_path=source_file_path1, prediction_with_BR=2, prediction_without_BR=2)
_add_sp(pattern='token', output_path=source_file_path2, prediction_with_BR=0, prediction_without_BR=1)
_add_sp(pattern='temp', output_path=source_file_path1, prediction_with_BR=1, prediction_without_BR=2)


class SearchWithBusinessRulesTestCase(unittest.TestCase):

    def test_TC01_Input_file_must_exist(self):
        self.assertTrue(os.path.isfile(source_file_path1))
        self.assertTrue(os.path.isfile(source_file_path2))

    def test_TC02_Are_all_BR_patterns_found_as_predicted(self):
        self._evaluate_result(True)

    def test_TC03_Are_all_patterns_found_as_predicted_Without_applying_BRs(self):
        self._evaluate_result(False)

    def test_TC04_http_in_tag_extension(self):
        """ Do this separate to avoid duplicate 'http' key. """
        global predictions
        predictions = {}
        _add_sp(pattern='http', output_path=source_file_path3, prediction_with_BR=1, prediction_without_BR=2)
        self._evaluate_result(False)
        self._evaluate_result(True)

    def _evaluate_result(self, apply_brs):
        FP_findings_counts = self._check_prediction(apply_brs)

        for row in FP_findings_counts:
            pattern_name = row[0]
            found_count = int(row[1])
            pred_col = 1 if apply_brs else 2
            pred_count = int(predictions[pattern_name][pred_col])
            apply_brs_text = 'With' if apply_brs else 'Without'
            self.assertTrue(
                found_count == pred_count,
                f"{apply_brs_text} applying BRs '{pattern_name}' was found {found_count} times, "
                f'predicted was {pred_count} times.'
            )

    @staticmethod
    def _check_prediction(apply_brs=True):
        """
        Scan the BR_patterns defined above.
        Count the total no. of findings in "UT_BR_patterns.txt" (as defined above).
        """
        FP_findings_counts = []
        scanner.apply_business_rules = apply_brs
        for prediction in predictions.values():
            sp = prediction[0]
            # Scan 1 source (the one with all patterns)
            scanner.scan_source(sp.output_subfolder_name, sp)
            # Assertion of no. of findings found (except for FP patterns)
            FP_findings_counts.append([sp.pattern_name, scanner.total_findings_for_this_source])
        return FP_findings_counts

    def test_TC03_Special_BRs(self):
        BRManager = BusinessRuleManager()
        self.assertTrue(BRManager.exclude('<%@page contentType="text/html"%>', 'email', pos=2, file_ext='.jsp'))
        self.assertFalse(BRManager.exclude('<T@page contentType="text/html"%>', 'email', pos=2, file_ext='.jsp'))


if __name__ == '__main__':
    unittest.main()
