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
from src.core.Functions.Functions import get_root_dir
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Validate import *

model = CoreModel()

# Directories
search_manager = SearchPattern_Manager()

base_dir = f'{get_root_dir()}UT/Project/specific'
Session().set_paths(unit_test=True)
output_dir = normalize_dir(Session().log_dir + 'UT_SearchPatterns', create=True)
scanner: Scanner
scanner_started = False


def get_scanner():
    global base_dir, scanner, scanner_started
    # The file_type to scan is *=All.
    if not scanner_started:
        scanner_started = True
        scanner = Scanner.Scanner(base_dir, file_type='*')
    return scanner


def scan_dir(pattern, pattern_name, apply_BRs=True):
    global scanner, output_dir
    # Configure Session
    Session().set_paths(unit_test=True, suffix=__name__)
    sp = SearchPattern(pattern, pattern_name, apply_business_rules=apply_BRs)

    # Scan 1 source (the one with all patterns)
    scanner.total_findings = 0
    scanner.scan_dir(sp, base=output_dir)
    # Mark if no findings are found.
    return scanner.total_findings


class SearchPatternTestCase(unittest.TestCase):

    def test_TC01_base_directory_must_exist(self):
        self.assertTrue(os.path.exists(base_dir))

    def test_TC02_Output_directory_must_exist(self):
        global output_dir
        output_dir = normalize_dir(Session().log_dir + 'UT_SearchPatterns', create=True)
        self.assertTrue(os.path.exists(output_dir))

    def test_TC03_Scanner_must_exist(self):
        global scanner
        scanner = get_scanner()
        self.assertIsNotNone(scanner)

    def test_TC04_Scan_authentication_start_tag(self):
        pattern = '<authentication'
        pattern_name = 'authentication_start_tag'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(2, result)

    def test_TC05__authentication_start_tag_with_attribute(self):
        pattern = '<authentication Mode='
        pattern_name = 'authentication_start_tag_with_attribute'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(2, result)

    def test_TC06__authentication_start_tag_with_attribute_value_doublequote(self):
        pattern = '<authentication mode="None"'
        pattern_name = 'authentication_start_tag_with_attribute_value_doublequote'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(1, result)

    def test_TC07__authentication_start_tag_with_attribute_value_singlequote(self):
        pattern = '<authentication mode=\'None\''
        pattern_name = 'authentication_start_tag_with_attribute_value_singlequote'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(1, result)

    def test_TC08__Regex_backtracking(self):
        pattern = ')*'
        pattern_name = 'regex_hook_asterisk'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(2, result)
        pattern = ')+'
        pattern_name = 'regex_hook_plus'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(2, result)

    def test_TC09__pickle(self):
        pattern = 'pickle'
        pattern_name = 'pickle'
        result = scan_dir(pattern, pattern_name)
        self.assertEqual(2, result)


if __name__ == '__main__':
    unittest.main()
