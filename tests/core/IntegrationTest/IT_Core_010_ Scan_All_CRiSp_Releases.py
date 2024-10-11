#!/usr/bin/python
# ---------------------------------------------------------------------------------------------------------------------
# UT_Core_500_Report.py
#
# Author      : Peter Heijligers
# Description : import a Findings.csv, and create a FindingsStatus report with it.
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-03-09 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import unittest
from os import listdir
from os.path import isdir, join

import src.core.BusinessLayer.CRiSpy
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import MODULE_DB, SEARCH_DATA_PATH
from src.gl.Validate import *

CRiSp_releases_dir = EMPTY
top_level_dirs = EMPTY


class ScanAllCRiSpReleasesTestCase(unittest.TestCase):

    def test_TC01_CRiSp_releases_dir_must_exist(self):
        global CRiSp_releases_dir
        current_dir = os.path.dirname(os.path.realpath(__file__))
        index = str.find(current_dir, 'CRiSp')
        self.assertGreater(index, 0)
        CRiSp_releases_dir = normalize_dir(current_dir[:index] + 'CRiSp/UT/UT_Releases/Project-CRiSp')
        self.assertTrue(os.path.isdir(CRiSp_releases_dir))

    def test_TC02_Get_top_level_dirs(self):
        global CRiSp_releases_dir, top_level_dirs
        top_level_dirs = [d for d in listdir(CRiSp_releases_dir) if isdir(join(CRiSp_releases_dir, d))]
        # and "/" not in d and "\\" not in d)
        self.assertTrue(len(top_level_dirs) > 0)

    def test_TC03_Scan_Releases(self):
        global CRiSp_releases_dir, top_level_dirs
        top_level_dirs.sort()
        for dir_name in top_level_dirs:
            print('Starting CRiSp for directory {}.'.format(dir_name))
            self.start_crisp(input_dir=CRiSp_releases_dir + dir_name, title=dir_name, company='CRiSp_BV')

    @staticmethod
    def start_crisp(input_dir=EMPTY,
                    title=EMPTY,
                    company=EMPTY,
                    custom_pattern=SEARCH_DATA_PATH,
                    verbose=False,
                    filter_mode=True):
        # Configure Session
        Session().set_paths(unit_test=True, module_name=MODULE_DB, suffix=title)

        # Start CRiSp
        crispy = src.core.BusinessLayer.CRiSpy.CRiSpy(
            input_dir=input_dir,
            log_title=title,
            company_name=company,
            custom_search_pattern=custom_pattern,
            verbose=verbose,
            filter_findings=filter_mode
        )
        crispy.start(unit_test=True)


if __name__ == '__main__':
    unittest.main()
