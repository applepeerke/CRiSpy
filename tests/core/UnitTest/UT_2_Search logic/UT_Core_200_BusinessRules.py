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

from src.core.BusinessLayer.BusinessRuleManager import BusinessRuleManager
from src.core.DataLayer.BusinessRule import *
from src.core.DataLayer.CoreModel import FD, SEARCH_PATTERNS
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session

session = Session()
session.set_paths(unit_test=True)

EMPTY = ""

br_manager = BusinessRuleManager()
csv_manager = CsvManager()
business_rules = []
search_patterns = []


# BusinessRules rows
# ------------------
# 0 = PatternName
# 1 = FileName
# 2 = Ext
# 3 = Seq
# 4 = SearchValue
# 5 = RuleOperator
# 6 = Status


class BusinessRulesTestCase(unittest.TestCase):

    def test_TC01_Business_rules_must_exist(self):
        global business_rules
        br_manager.populate_business_rules()
        business_rules = br_manager.business_rules
        self.assertGreater(len(business_rules), 0)

    def test_TC02_Search_patterns_must_exist(self):
        global search_patterns
        rows = csv_manager.get_rows(True, data_path=os.path.join(session.import_dir, f'{SEARCH_PATTERNS}.csv'))
        self.assertGreater(len(rows), 1)
        # 5 = PatternName
        index = rows[0].index(FD.SP_Pattern_name)
        self.assertGreater(index, -1)
        search_patterns = [row[index].lower() for row in rows[1:]]
        self.assertGreater(len(search_patterns), 0)

    def test_TC03_Check_Business_Rules(self):
        i = 0
        for br in business_rules:
            i += 1
            prefix = 'Business rule row ' + str(i) + ': '
            self.assertIsInstance(br, BusinessRule,
                                  f'{prefix} Row is not a BusinessRule type.')
            if br.pattern_name != '*':
                self.assertIn(br.pattern_name.lower(), search_patterns,
                              f'{prefix} Pattern name does not exist in SearchPatterns.csv.')
            if br.rule_operator != EMPTY:
                self.assertTrue(hasattr(RuleOperator, br.rule_operator),
                                f'{prefix} Rule operator does not exist in RuleOperator.')
            if br.file_ext:
                exts = br.file_ext.split(',')
                for e in exts:
                    self.assertTrue(str(e).isalpha(),
                                    f'{prefix} Extension is not completely alphabetic.')


if __name__ == '__main__':
    unittest.main()
