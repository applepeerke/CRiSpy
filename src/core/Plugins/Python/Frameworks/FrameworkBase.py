# ---------------------------------------------------------------------------------------------------------------------
# FrameworkBase.py
#
# Author      : Peter Heijligers
# Description : Framework base
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-10-26 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Enums import HttpMethods
from src.core.Plugins.Python.Frameworks.Decorators import Decorator
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Const import CSV_EXT
from src.gl.Enums import Output
from src.gl.GeneralException import GeneralException

PGM = 'FrameworkBase'

# File headers
HEADER_INPUT = ['ScanFor']
HEADER_DECORATORS = ['Subject', 'Decorator', 'Company']


class FrameworkBase(object):

    @property
    def api_method_names(self):
        return self._api_method_names

    @property
    def input_names(self):
        return self._input_names

    @property
    def decorators(self):
        return self._decorators

    def __init__(self):
        self._scanner = None
        self._session = None
        self._started = False
        self._input_names = []
        self._api_method_names = list(HttpMethods.all)
        self._decorators = set()
        self._isFramework = False

    def is_framework(self, session, scanner) -> bool:
        if self._started:
            return self._isFramework
        self._started = True
        self._session = session
        self._scanner = scanner
        self._scanner.file_type = 'py'
        self._get_input_names()
        self._start_specific()
        return self._try_framework()

    def _start_specific(self):
        pass

    def _get_input_names(self):
        pass

    def _try_framework(self) -> bool:
        """
        is a framework pattern found ?
        """
        self._isFramework = any(self._scanner.scan_dir(
            sp=SearchPattern(pattern=i, include_comment=True), output=Output.Object) for i in self._input_names)
        return self._isFramework

    def _get_decorators(self):
        rows = self._get_rows('Decorators', HEADER_DECORATORS)
        for row in rows:
            self._decorators.add(
                Decorator(
                    subject=row[0],
                    decorator=row[1],
                    company_name=row[2]))

    def _get_rows(self, filename, header_def: list) -> []:
        path = f'{self._session.plugins_dir}{filename}{CSV_EXT}'
        rows = CsvManager().get_rows(data_path=path, include_header_row=True)
        if not rows:
            self._raise(f'Required file not found', path)
        header_row = rows[0]
        if len(header_row) != len(header_def):
            self._raise(f'Incorrect header length. Expected {len(header_def)} but found {len(header_row)}', path)
        for i in range(len(header_row)):
            if header_row[i] != header_def[i]:
                self._raise(f"Incorrect header column. Expected '{header_def[i]}' but found '{i}'", path)
        return rows[1:]

    def _raise(self, message, path):
        raise GeneralException(f"{__name__}: {message}. Path is '{path}'")
