# ---------------------------------------------------------------------------------------------------------------------
# RestManager.py
#
# Author      : Peter Heijligers
# Description : RestFramework manager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-08-18 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.Plugins.Python.Frameworks.FrameworkBase import FrameworkBase, HEADER_INPUT

PGM = 'RestManager'


class RestManager(FrameworkBase):

    def __init__(self):
        super().__init__()

    def _start_specific(self):
        self._get_decorators()

    def _get_input_names(self):
        self._input_names = ['apiview', 'rest_framework.request', 'api_view']
        rows = self._get_rows('RestFramework_inputs', HEADER_INPUT)
        for row in rows:
            self._input_names.append(row[0])
