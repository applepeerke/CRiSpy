# ---------------------------------------------------------------------------------------------------------------------
# AuthorizationManager.py
#
# Author      : Peter Heijligers
# Description : Manage AuthorizationPatterns.csv
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-10-13 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session

csvm = CsvManager()
session = Session()


class AuthorizationManager(object):

    def __init__(self):
        self._patterns = []
        self._initialized = False

    @property
    def patterns(self):
        self._get_patterns()
        return self._patterns

    def _get_patterns(self):
        if not self._initialized:
            if session and session.import_dir and session.company_name:
                data_path = f'{session.import_dir}AuthorizationPatterns.csv'
                rows = csvm.get_rows(include_header_row=False, data_path=data_path )
                self._patterns = [row[1] for row in rows if len(row) > 1 and row[0] == session.company_name]
        self._initialized = True
