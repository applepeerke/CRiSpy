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
import os
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.core.DataLayer.CoreModel import *
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import EMPTY, ALL, CATEGORY_GENERAL, CATEGORY_LANGUAGE, CATEGORY_COMPANY, NONE
from src.gl.Validate import normalize_dir

model = CoreModel()

# Directories
SP_manager = SearchPattern_Manager()
Session().set_paths(unit_test=True)
input_dir = Session().import_dir

patterns_file_name = 'SearchPatterns.csv'
input_patterns_path = f'{input_dir}{patterns_file_name}'
input_source_path = input_patterns_path
output_dir = normalize_dir(Session().log_dir + 'UT_SearchPatterns', create=True)

generals = [ALL]
languages = ['NET', 'Java', 'Python', 'PHP', 'C', 'HTML', 'Ruby', 'JavaScript', 'AngularJS', 'React', 'Scala']
companies = ['KPN', 'ilionx', 'Lyanthe']

all_searched_pattern_names = set()
not_scanned_pattern_names = []
search_count = -1
compensate = 0
error_messages = []
scan_results: list = []


class ScanResult(object):
    def __init__(self, pattern_file=EMPTY, category_list: list = None):
        self._pattern_file = pattern_file
        self._category_list = category_list

    regex_count = 0
    double_quote_count = 0
    total_findings = 0
    pattern_names_without_matches = []
    scan_figures = {}


def scan_search_pattern_file():
    global generals, languages, companies

    # The file_type to scan is *=All.
    scanner = Scanner.Scanner(input_dir, file_type='*')

    # A. Do a search for General.
    for general in generals:
        search(scanner, category=CATEGORY_GENERAL, value=general)

    # B. Do a search for every language.
    for language in languages:
        search(scanner, category=CATEGORY_LANGUAGE, value=language)

    # C. Do a search for every company.
    for company in companies:
        search(scanner, category=CATEGORY_COMPANY, value=company)

    print('-----------------------------------------------------------------------------------------------------------')


def print_score(result_dict, key, value):
    # Not searched for, ignore.
    if key not in SP_manager.selections:
        return

    filter_value = SP_manager.selections[key] or [ALL]
    filter_value = filter_value[0] if filter_value[0] != ALL else '*'

    # Not searched for, no findings is OK.
    if result_dict[key] == 0 and filter_value == NONE:
        return

    rest = 16 - len(key)
    dots = ' . . . . .'[:rest] if rest > 0 else EMPTY
    print(f'{key}{dots}: {str(result_dict[key])} - {filter_value}')
    if result_dict[key] == 0:
        error_messages.append(
            f'Expected but no matches found: {value} in {filter_value}')


def search(scanner, category, value):
    """
    Scan the target source with selected patterns.
    The target source is a source that contains all patterns.
    """
    global output_dir, search_count, scan_results
    scan_result = ScanResult(input_patterns_path, category_list=[category, value])
    result_dict = {
        CATEGORY_GENERAL: 0,
        CATEGORY_LANGUAGE: 0,
        CATEGORY_COMPANY: 0
    }
    search_count += 1

    print('-----------------------------------------------------------------------------------------------------------')
    print('Pattern file    : ' + input_patterns_path)
    # Clear output directory (be careful!)
    if os.path.exists(output_dir) and output_dir.endswith('UT_Search_patterns'):
        for root, dirs, files in os.walk(output_dir, topdown=False):
            for file_name in files:
                if file_name.endswith('.txt') or file_name.endswith('.csv'):
                    os.remove(os.path.join(output_dir, file_name))
        os.rmdir(output_dir)
        print('Output directory: "' + output_dir + '" has been removed.')
    output_dir = normalize_dir(output_dir, create=True)

    # Here 1 item per time
    search_patterns = SP_manager.get_valid_search_patterns(
        data_path=input_patterns_path,
        languages=[value] if category == CATEGORY_LANGUAGE else [NONE],
        companies=[value] if category == CATEGORY_COMPANY else [NONE],
        general=True if category == CATEGORY_GENERAL else False
    )
    total_regex = 0
    total_doublequote = 0
    total_findings = 0
    for sp in search_patterns:
        all_searched_pattern_names.add(sp.pattern_name)  # remember the pattern_names searched.
        result_dict[sp.category_name] += 1

        if str(sp.pattern).startswith('r"'):
            # Skip regex patterns
            total_regex += 1
        elif '"' in str(sp.pattern):
            # Skip '"' patterns
            total_doublequote += 1
        else:
            # Scan 1 source (the one with all patterns)
            sp.search_only_for = EMPTY
            scanner.scan_source(input_source_path, sp)
            # Mark if no findings are found.
            if scanner.total_findings_for_this_source == 0:
                scan_result.pattern_names_without_matches.append(sp.pattern_name)
            total_findings += 1

    line = 'Total findings  : ' + str(total_findings)
    if total_regex > 0:
        line += ' (Regex skipped: ' + str(total_regex) + ')'
    if total_doublequote > 0:
        line += ' (DoubleQuote skipped: ' + str(total_doublequote) + ')'
    print(line)
    print_score(result_dict, CATEGORY_GENERAL, value)
    print_score(result_dict, CATEGORY_LANGUAGE, value)
    print_score(result_dict, CATEGORY_COMPANY, value)

    # Store scan_result
    scan_result.total_findings = total_findings
    scan_result.regex_count = total_regex
    scan_result.double_quote_count = total_doublequote
    scan_result.scan_figures = result_dict

    scan_results.append(scan_result)


class SearchPatternsTestCase(unittest.TestCase):

    def test_TC01_Input_files_must_exist(self):
        self.assertTrue(os.path.isfile(input_patterns_path))

    # def test_TC02_Output_directory_must_exist(self):
    #     self.assertTrue(os.path.exists(output_dir))

    def test_TC03_Is_search_patterns_file_populated(self):
        global not_scanned_pattern_names

        # Check if patterns exist
        all_search_pattern_names = set(
            [sp.pattern_name for sp in SP_manager.get_valid_search_patterns(
                data_path=input_patterns_path, languages=[ALL])])
        self.assertGreater(len(all_search_pattern_names), 190)

        # Scan all 3 categories in SearchPattern file
        scan_search_pattern_file()
        self.assertTrue(len(error_messages) == 0, msg=error_messages)

        # Check sum of all categories
        not_scanned_pattern_names = [p for p in all_search_pattern_names if p not in all_searched_pattern_names]
        diff = SP_manager.total_pattern_count - sum(SP_manager.pattern_counts_per_category_dict.values())
        self.assertTrue(diff == 0, msg=f'Not scanned pattern names: {not_scanned_pattern_names}. '
                                       f'Sum of category counts is not equal to total pattern count in '
                                       f'SearchPattern file, difference is {diff}.')

    def test_TC04_Are_all_search_patterns_found(self):
        global compensate

        for sr in scan_results:
            # remove the *CF_ pattern names
            if 'hardcoded_key' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('hardcoded_key')
                compensate += 1
            if 'reDoS' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('reDoS')
                compensate += 1
            if 'logger' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('logger')
                compensate += 1
            if 'print' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('print')
                compensate += 1
            if 'getattr' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('getattr')
                compensate += 1
            if 'SELECT' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('SELECT')
                compensate += 1
            if 'WHERE' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('WHERE')
                compensate += 1
            if 'resources' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('resources')
                compensate += 1
            if 'actions' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('actions')
                compensate += 1
            if 'principals' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('principals')
                compensate += 1
            if 'email' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('email')
                compensate += 1
            if 'verify' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('verify')
                compensate += 1
            if 'href' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('href')
                compensate += 1
            if 'script' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('script')
                compensate += 1
            if 'src' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('src')
                compensate += 1
            if 'onload' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('onload')
                compensate += 1
            if 'input' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('input')
                compensate += 1
            if 'log' in sr.pattern_names_without_matches:
                sr.pattern_names_without_matches.remove('log')
                compensate += 1
            # Only the ones that have a special constraint "AssignedTo" are not found.
            for p in ['pass', 'pwd', 'token', 'login', 'otp', 'phone', 'secret']:
                if p in sr.pattern_names_without_matches:
                    sr.pattern_names_without_matches.remove(p)

            self.assertTrue(sr.pattern_names_without_matches == [],
                            f'The following pattern names are not found: '
                            f'{str(sr.pattern_names_without_matches)} in \n {input_patterns_path}')

    def test_TC05_Are_all_search_patterns_scanned(self):
        global compensate
        scanned_count = 0
        for sr in scan_results:
            scanned_count += \
                sr.scan_figures[CATEGORY_GENERAL] + \
                sr.scan_figures[CATEGORY_LANGUAGE] + \
                sr.scan_figures[CATEGORY_COMPANY]
        # to_check_patterns_count = SP_manager.total_pattern_count - compensate
        self.assertEqual(
            scanned_count, SP_manager.total_pattern_count,
            msg=f'of {SP_manager.total_pattern_count} patterns {scanned_count} are scanned '
                f'(compensated are {compensate}). Not scanned are {not_scanned_pattern_names}')


if __name__ == '__main__':
    unittest.main()
