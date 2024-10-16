#!/usr/bin/python
# ---------------------------------------------------------------------------------------------------------------------
# UT_Core_400_SearchPatterns.py
#
# Author      : Peter Heijligers
# Description : Process SearchPatterns.csv and look if all search patterns generate findings in itself...
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-10-10 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.core.DataLayer.CoreModel import CoreModel
from src.core.DataLayer.SearchPattern import SearchPattern
from root_functions import get_root_dir
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Validate import *

model = CoreModel()

# Directories
search_manager = SearchPattern_Manager()
current_dir = os.path.dirname(os.path.realpath(__file__))

Session().set_paths(unit_test=True)
base_dir = f'{get_root_dir()}UT/Project/specific_file/'
output_dir = normalize_dir(Session().log_dir + 'UT_SearchPatterns', create=True)
scanner = Scanner.Scanner(base_dir, file_type='*')


class SearchPatternTestCase(unittest.TestCase):

    def test_TC01_Find_Http(self):
        sp = SearchPattern(pattern='r"^(?!.*(soap|xmlns|namespace|www.w3.org)).*(http://)"', pattern_name='http')
        scanner.apply_business_rules = True
        scanner.scan_source(f'{base_dir}http.txt', sp)
        self.assertTrue(
            scanner.total_findings_for_this_source == 2,
            f'Expected: 2, Found: {scanner.total_findings_for_this_source}')


if __name__ == '__main__':
    unittest.main()
