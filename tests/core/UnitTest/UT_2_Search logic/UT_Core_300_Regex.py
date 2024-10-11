import os
import re
import unittest

from src.core.BusinessLayer import Scanner as Scanner
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager as SearchPattern_Manager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import CSV_SEARCH_PATTERNS

Session().set_paths(unit_test=True)
current_dir = os.path.dirname(os.path.realpath(__file__))

# Directories
SP_manager = SearchPattern_Manager()
regex_patterns = []
input_dir = Session().design_dir
patterns_file_name = CSV_SEARCH_PATTERNS
patterns_path = Session().import_dir + patterns_file_name
target_file = 'UT_Regex_patterns.txt'
target_file_customer = 'UT_Regex_patterns_customer.txt'
target_source_path = input_dir + target_file
regex_count = 0
regex_findings_counts = []
# The file_type to scan is *=All.
scanner = Scanner.Scanner(input_dir, file_type='*')


def regex(line, sp):
    result = re.search(sp, line, re.IGNORECASE)
    return True if result else False


def find_string(line, sp):
    if sp.startswith('r"'):
        return True if regex(line, sp[2:len(sp) - 1]) else False  # Skip the "r" and trailing ""
    # b. Find
    else:
        return line.lower().find(sp.lower()) > 0


def descape(special_chars, line):
    return "".join(c for c in special_chars if c in line)


class RegexTestCase(unittest.TestCase):

    def test_TC01_SHA_followed_by_1_to_4_digits(self):

        # "SHA" using find_file
        self.assertGreater(find_string('Find sha', 'SHA'), 0)
        self.assertEqual(find_string('Do NOT find_file SHihA', 'SHA'), 0)
        self.assertGreater(find_string('Still find_file shadow :-(', 'SHA'), 0)
        self.assertFalse(find_string('Do NOT find_file sha1. No supported regex', '(SHA)[0-9]{1,4}'))
        # "SHA" using Regex
        self.assertTrue(find_string('Do find_file sha0 followed by 0.', 'r"(SHA)[0-1]"'))
        self.assertTrue(find_string('Do find_file sha1 followed by 1.', 'r"(SHA)[0-1]"'))
        self.assertFalse(find_string('Do NOT find_file sha. or sha2 or SHA256', 'r"(SHA)[0-1]"'))
        self.assertFalse(find_string('Do NOT find_file sha NOT followed by a number.', 'r"(SHA)[0-9]{1,4}"'))
        self.assertTrue(find_string('Find sha1 followed by 1-4 numbers.', 'r"(SHA)[0-9]{1,4}"'))
        self.assertTrue(find_string('Find SHA16 text', 'r"(SHA)[0-9]{1,4}"'))
        self.assertTrue(find_string('Find sha256 text', 'r"(SHA)[0-9]{1,4}"'))
        self.assertTrue(find_string('Find sha1024 text', 'r"(SHA)[0-9]{1,4}"'))
        self.assertTrue(find_string('Find sha10245 text', 'r"(SHA)[0-9]{1,4}"'))  # Error in regex?
        self.assertFalse(find_string('SharedHighAssets1 contains NOT vulnarable text', 'r"(SHA)[0-9]{1,4}"'))

    def test_TC02_http_in_combination_with_xmlns(self):

        self.assertTrue(find_string('Find http://mySite', 'r"^(?!.*xmlns).*(http://)"'))
        self.assertFalse(find_string('Do NOT find_file http://mySite.xmlns', 'r"^(?!.*xmlns).*(http://)"'))

        # TODO: Strange enough this doesn't work.'
        # assert not regex('This line contains sha10240 text', r"[SHA]\d{1,4}")
        # assert not regex('This line contains sha102406 text', r"[SHA]\d{1,4}")

    def test_TC03_Double_slash(self):

        expr = 'r"^(?!.*http).*(//)"'
        self.assertFalse(find_string('Find http://mySite', expr))
        self.assertTrue('Find // my comment', expr)

    def test_TC04_Escape_and_Descape(self):

        specialChars = '%^&$#$*()-_+="'
        inputString = '%^&$#$*()-_+="'
        output = re.escape(inputString)
        self.assertNotEqual(inputString, output)
        output = descape(specialChars, output)
        self.assertEqual(inputString, output)

    def test_TC05_Guid(self):

        expr = 'r"[0-9a-z]{20,80}"'
        self.assertTrue(
            find_string('Find dSDjdfoknSndi88sdjwEknw3us3iU8sdfnau8yEfjnfao8rYwernjSaeoys correct', expr))
        self.assertFalse(find_string('Find dSDjdfoknsndi88sdj_weknw3us3iu8sdf wrong "_"', expr))
        self.assertFalse(find_string('Find dSDjdfoknsnd too short', expr))

    def test_TC06_email(self):
        expr = 'r"(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"'
        self.assertTrue(find_string('Find hi.fellow@hotmail.com', expr))
        self.assertTrue(find_string('Find fellow@hotmail.com', expr))
        self.assertFalse(find_string('Do NOT Find hi.fellow@hotmailcom', expr))
        self.assertFalse(find_string('Do NOT Find @hotmail.com', expr))
        self.assertFalse(find_string('Do NOT Find hi.fellow.hotmail.com@', expr))
        TEXT_REGEX = re.compile(r"^\w+([-_.+]\w+)*-?@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
        expr = 'r"\S@\w"'
        self.assertTrue(find_string('Find hi.fellow@hotmail.com', expr))
        self.assertTrue(find_string('Find fellow@hotmail.com', expr))
        self.assertTrue(find_string('Find hi.fellow@hotmailcom', expr))  # This is a difference
        self.assertFalse(find_string('Do NOT Find @hotmail.com', expr))
        self.assertFalse(find_string('Do NOT Find hi.fellow.hotmail.com@', expr))

    def test_TC07_alg_none(self):

        expr = 'r"{[ \"]+alg[ \"]+:[ \"]+none[ \"]+}"'
        self.assertTrue(find_string('  { alg : none } ', expr))
        self.assertTrue(find_string('{"alg":"none"}', expr))
        self.assertTrue(find_string(' { "alg" : "none" } ', expr))
        self.assertFalse(find_string('Do NOT Find alg none', expr))
        self.assertFalse(find_string('Do NOT Find alg: none', expr))

    def test_TC08_customer_expressions(self):
        """
        Test that Malicious scripts can not occur in regex expressions that are validating text fields
        """
        # KPN project nb-iot-lora:  Define re-usable compiled regex objects
        TEXT_REGEX = re.compile(r"^[?.!#|@+'`~^%&$;,:=/*\[\]\\\"()\-\w\s]*$")

        path = input_dir + target_file_customer
        with open(path) as f:
            content = f.readlines()
        for line in content:
            if 'TEXT_REGEX' in line:
                if re.match(TEXT_REGEX, line) and 'Do NOT Find' in line:
                    self.fail(f"TEXT_REGEX line was valid but should NOT be. Line: '{line}'.")
                elif not re.match(TEXT_REGEX, line) and 'Do NOT Find' not in line:
                    self.fail(f"TEXT_REGEX line was NOT valid but should be. Line: '{line}'.")


class SearchWithRegexTestCase(unittest.TestCase):

    def test_TC01_Input_file_must_exist(self):
        self.assertTrue(os.path.isfile(patterns_path))

    def test_TC02_Are_5_regex_patterns_present(self):
        global regex_patterns
        # Get all search patterns
        SP_manager.filter_cols = []
        search_patterns = SP_manager.get_valid_search_patterns(patterns_path)
        regex_patterns = []
        for sp in search_patterns:
            if str(sp.pattern).startswith('r"'):
                regex_patterns.append(sp)
        self.assertEqual(len(regex_patterns), 5)

    def test_TC03_Are_all_regex_patterns_found_as_predicted(self):
        global regex_count, regex_findings_counts
        regex_count = 0
        prediction = {'SHA': 2,
                      'http': 1,
                      'doubleslash': 1,
                      'email': 1,
                      'MA': 1,
                      'external_parties': 1,
                      'hardcoded_key': 0,
                      'algnone': 0,
                      }
        for sp in regex_patterns:
            regex_count += 1
            sp.apply_business_rules = False
            # Scan 1 source (the one with all patterns)
            scanner.scan_source(target_source_path, sp)
            # Assertion of no. of findings found (except for regex patterns)
            regex_findings_counts.append([sp.pattern_name, scanner.total_findings_for_this_source])
        for findings_count in regex_findings_counts:
            if findings_count[0] not in prediction:
                self.fail('Pattern name "' + findings_count[0] + '" was not found in the prediction.')
            else:
                self.assertEqual(findings_count[1], prediction[findings_count[0]],
                                 'Pattern name "' + findings_count[0] + '" was not found the times predicted.')


if __name__ == '__main__':
    unittest.main()
