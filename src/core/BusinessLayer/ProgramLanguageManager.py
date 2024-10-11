#  ---------------------------------------------------------------------------------------------------------------------
# ProgramLanguageManager.py
#
# Author      : Peter Heijligers
# Description : Manages ProgramLanguages.csv.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-11-29 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.ProgramLanguage import ProgramLanguage
from src.gl.BusinessLayer.CsvManager import CsvManager as Data_Manager
from src.gl.Validate import toBool

EMPTY = ''


class ProgramLanguageManager:

    @property
    def language_dict(self):
        return self._language_dict

    @property
    def languages(self):
        return self._languages

    @property
    def language_names(self):
        return self._language_names

    def __init__(self):
        self._data_manager = None
        self._data_rows = None
        # Set properties
        self._language_dict = None
        self._languages = set()
        self._language_names = []

    def construct(self):
        if self._data_manager is None:
            # Get data
            self._data_manager = Data_Manager()
            self._data_manager.file_name = 'ProgramLanguages.csv'
            self._data_rows = self._data_manager.get_rows()
            # Set properties
            self._language_dict = {row[0]: self._row_to_object(row) for row in self._data_rows if row[0]}

    def set_languages(self, file_extensions):
        """
        a. Map file extensions to Languages
        b. List included and excluded file types for in the _log.
        """
        self._languages = set(self.language_dict[ext] for ext in file_extensions if ext in self.language_dict)
        self._language_names = [Language.language_name for Language in self._languages]

    def get_language(self, ext) -> ProgramLanguage or None:
        if not ext:
            return None
        if not ext.startswith('.'):
            ext = f'.{ext}'
        return self._language_dict.get(ext) if self._language_dict else None

    @staticmethod
    def _row_to_object(row) -> ProgramLanguage:
        """
        0 = FileExt
        1 = Language name
        2 = SecurityHeaders (may contain)
        """
        return ProgramLanguage(row[0], row[1], toBool(row[2], default=True))
