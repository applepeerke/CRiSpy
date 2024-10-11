import os
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.core.DataLayer.SearchPattern import SearchPattern

session = Session()
search_manager = SearchPattern_Manager()

session.set_paths(unit_test=True)

# Directories
input_dir = session.design_dir
scanner = Scanner.Scanner(input_dir, file_type='*')

file_name = 'UT_IsComment.test'


class SearchPatternIsCommentTestCase(unittest.TestCase):

    def test_TC01_Input_file_must_exist(self):
        self.assertTrue(os.path.isfile(f'{input_dir}{file_name}'))

    def test_TC02_Find_Constant(self):
        sp = SearchPattern(pattern='dump', pattern_name='dump', include_comment=False)
        scanner.apply_business_rules = False
        scanner.initialize_scan()
        scanner.scan_source(f'{input_dir}{file_name}', sp)
        expected = 1
        self.assertTrue(
            scanner.total_findings_for_this_source == expected,
            f'Expected: {expected}, Found: {scanner.total_findings_for_this_source}')


if __name__ == '__main__':
    unittest.main()
