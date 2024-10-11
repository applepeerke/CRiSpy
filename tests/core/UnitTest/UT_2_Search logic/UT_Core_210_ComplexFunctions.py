import os
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.BusinessLayer.ComplexFunctions import \
    CF_HARDCODED_KEY, CF_REDOS, CF_LOGGER, CF_PARM_CHECK, CF_TRACE, CF_RESOURCES, CF_EMAIL, CF_VERIFY, \
    CF_HEADER, CF_SCRIPT, CF_PHONE, CF_INPUT, CF_AUTOESCAPE
from src.gl.Const import EMPTY

session = Session()
search_manager = SearchPattern_Manager()

session.set_paths(unit_test=True)
current_dir = os.path.dirname(os.path.realpath(__file__))

# Directories
input_dir = session.design_dir
scanner = Scanner.Scanner(input_dir, file_type='*')

AUTOESCAPE = 'autoescape'
GETATTR = 'getattr'
VERIFY = 'verify'
HREF = 'href'
SRC = 'src'
ONLOAD = 'onload'
INPUT = 'input'

default_patterns = {
    CF_INPUT: [INPUT],
    CF_EMAIL: ['email'],
    CF_HARDCODED_KEY: ['Hardcoded_key'],
    CF_HEADER: ['header'],
    CF_LOGGER: ['logger'],
    CF_PARM_CHECK: [GETATTR],
    CF_REDOS: ['ReDos'],
    CF_RESOURCES: ['resources'],
    CF_SCRIPT: [HREF, SRC, ONLOAD],
    CF_TRACE: ['trace'],
    CF_VERIFY: [VERIFY],
    CF_AUTOESCAPE: [AUTOESCAPE],
    CF_PHONE: ['phone']
}
pattern_parms = {
    AUTOESCAPE: '(contains, or, false, none)',
    GETATTR: '(getattr)',
    VERIFY: '(contains, or, false, none)',
    HREF: '(href)',
    SRC: '(src)',
    ONLOAD: '(onload)',
    INPUT: '(<input)'

}

found_count = 0


def scan_line(sp, file_name, line):
    global found_count
    index = scanner.scan_line(sp, file_name, '.txt', line, apply_BRs=False)
    if index > -1:
        found_count += 1


class SearchWithComplexFunctionsTestCase(unittest.TestCase):

    def test_TC01_Find_patterns_default_tests(self):
        for pattern_category, pattern_names in default_patterns.items():  # e.g. *CF_SCRIPT, ['script', href',...]
            for pattern_name in pattern_names:
                if len(pattern_names) > 1:
                    category = f'{pattern_category[4:]}'
                    suffix = f'_{pattern_name}'
                else:
                    category = pattern_name
                    suffix = EMPTY
                path = f'{input_dir}UT_CF_{category}{suffix}.txt'
                self._predict(
                    path,
                    SearchPattern(
                        pattern=f'{pattern_category}{pattern_parms.get(pattern_name) or EMPTY}',
                        pattern_name=pattern_name),
                )

    def test_TC02_Find_Specific(self):
        global found_count
        found_count, expected = 0, 2
        path = f'{input_dir}UT_CF_reDoS.txt'
        sp = SearchPattern(pattern=CF_REDOS, pattern_name='reDoS')
        scan_line(sp, path, line=' Find repeatable "+"    = (\\d+)+')
        scan_line(sp, path, line=' Do NOT find_file simple "+" = (\\d)+')
        self.assertTrue(found_count == expected, f'Expected: {expected}, Found: {found_count}')

    def _predict(self, path, sp: SearchPattern):
        # Count the expected findings, i.e. lines containing ' Find ' in the source file.
        with open(path) as f:
            content = f.readlines()
        expected = len([line for line in content if line.find(' Find ') > -1])
        # Scan the source
        scanner.apply_business_rules = False
        scanner.scan_source(path, sp)
        # Analyze: prediction not met.
        error_flag = False
        if scanner.total_findings_for_this_source != expected:
            for line in content:
                should_be_found = line.find(' Find ') > -1
                should_not_be_found = line.find(' NOT find ') > -1
                if should_be_found or should_not_be_found:  # Line to test found (e.g. not empty line)
                    index = scanner.scan_line(sp, line=line, apply_BRs=False)
                    if should_not_be_found and index > -1:
                        error_flag = True
                        print(f"Pattern '{sp.pattern_name}' found but should NOT be found in line: '{line}'")
                    if should_be_found and index == -1:
                        error_flag = True
                        print(f"Pattern '{sp.pattern_name}' NOT found but should be found in line: '{line}'")
        # Ring the bell
        self.assertFalse(error_flag, msg='See printed lines.')
        # self.assertTrue(
        #     scanner.total_findings_for_this_source == expected,
        #     f"Expected for '{sp.pattern_name}': {expected}, Found: {scanner.total_findings_for_this_source}" )


if __name__ == '__main__':
    unittest.main()
