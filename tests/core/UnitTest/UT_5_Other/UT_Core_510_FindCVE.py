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

from src.core.BusinessLayer.CVEManager import CVEManager
from src.core.BusinessLayer.Scanner import Scanner
from root_functions import format_os
from src.core.Plugins.Versions.Versions_python import Versions_python
from src.gl.BusinessLayer.SessionManager import Singleton as Session, normalize_dir

Session().set_paths(unit_test=True)


class FindCVETestCase(unittest.TestCase):

    def test_TC01_Validate_installed_base(self):
        self.assertTrue(CVEManager().is_valid_installed_base())

    def test_TC02_Synchronize(self):
        #  Days - 1 day
        self._synchronize('2020-02-16', '2020-02-16', 0, 0, 0)
        self._synchronize('2020-02-16', '2020-02-17', 0, 0, 0)
        self._synchronize('2020-02-16', '2020-02-18', 0, 0, 0)
        self._synchronize('2020-02-16', '2020-02-19', 1, 0, 0)
        #  Days - 1 day - month passover
        self._synchronize('2020-01-31', '2020-02-01', 0, 0, 0)
        self._synchronize('2020-01-31', '2020-02-03', 0, 0, 1)
        self._synchronize('2020-01-31', '2020-02-04', 0, 0, 2)
        #  Days - 14 days
        self._synchronize('2020-01-01', '2020-01-16', 13, 0, 0)
        self._synchronize('2020-01-02', '2020-01-17', 13, 0, 0)
        #  Month - 1 month 14 days
        self._synchronize('2020-01-01', '2020-02-16', 30, 0, 14)
        self._synchronize('2020-12-20', '2021-01-05', 11, 0, 3)  # 12 days 21 tm 01, then 02-04
        #  Month - 36 months 14 days
        self._synchronize('2019-12-20', '2023-01-05', 11, 36, 3)  # 12 days 21 tm 2019-12-31, 36 months, then 02-04
        #  Month - 36 months 14 days
        self._synchronize('2023-02-24', '2023-03-22', 4, 0, 20)  # 6 days 24 tm 01, 0 months, then 02-21

    def test_TC03_FindCVE(self):
        self.assertTrue(len(self._find()) == 0, msg=f'Expected 0 but found {len(self._vulnerabilities)}')
        self.assertTrue(len(self._find('wordpress')) > 2,
                        msg=f'Expected > 2 but found {len(self._vulnerabilities)}')
        self.assertTrue(len(self._find('chrome')) > 20,
                        msg=f'Expected > 1260 but found {len(self._vulnerabilities)}')

    def test_TC04_Find_CVE_vulnerabilities_from_requirements_txt(self):
        input_dir = normalize_dir(f"{Session().design_dir}CVE{format_os('/')}2.0")
        Session().input_dir = input_dir
        versions_py = Versions_python(Scanner(input_dir))
        versions_py.run('requirements.txt')
        self.assertTrue(len(versions_py.versions_by_path) == 1,
                        msg=f'Expected 1, found {len(versions_py.versions_by_path)}')
        self.assertTrue(len(versions_py.potential_vulnerable_rows) > 60,
                        msg=f'Expected 60, found {len(versions_py.potential_vulnerable_rows)}')
        self.assertTrue(versions_py.CVE_vulnerability_count >= 1,
                        msg=f'Expected 2, found {versions_py.CVE_vulnerability_count}')

    def _find(self, product=None) -> list:
        self._vulnerabilities = CVEManager().search(product)
        return self._vulnerabilities

    def _synchronize(self, sync_ymd, now_ymd, days_before, months, days_after):
        CVM = CVEManager(test_sync_ymd=sync_ymd, test_now_ymd=now_ymd)
        CVM.synchronize()
        prefix = f'From {sync_ymd} to {now_ymd}: Expected '
        self.assertTrue(
            CVM.days_before_synchronized == days_before,
            msg=f'{prefix}{days_before} but got {CVM.days_before_synchronized} days to synchronize before.')
        self.assertTrue(
            CVM.months_synchronized == months,
            msg=f'{prefix}{months} but got {CVM.months_synchronized} months to synchronize.')
        self.assertTrue(
            CVM.days_after_synchronized == days_after,
            msg=f'{prefix}{days_after} but got {CVM.days_after_synchronized} days to synchronize after.')


if __name__ == '__main__':
    unittest.main()
