# ---------------------------------------------------------------------------------------------------------------------
# PrivacyManager.py
#
# Author      : Peter Heijligers
# Description : Manage PrivacyPatterns.csv
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-04-06 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session

csvm = CsvManager()


class PrivacyManager(object):

    def __init__(self):
        self._patterns = []

    @property
    def patterns(self):
        return self._patterns

    def set_patterns(self):
        if not self._patterns and Session() and Session().import_dir:
            data_path = f'{Session().import_dir}PrivacyPatterns.csv'
            rows = csvm.get_rows(include_header_row=False, data_path=data_path)
            self._patterns = [row[0] for row in rows]
