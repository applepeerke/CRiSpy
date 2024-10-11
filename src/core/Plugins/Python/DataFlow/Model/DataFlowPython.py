# ---------------------------------------------------------------------------------------------------------------------
# Endpoint.py
#
# Author      : Peter Heijligers
# Description : Parameter in a source file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-03-29 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.DataFlow import DataFlow


class DataFlowPython(DataFlow):

    @property
    def vulnerable(self):
        return self._vulnerable

    # Setters
    @vulnerable.setter
    def vulnerable(self, value):
        self._vulnerable = value

    def __init__(self, vulnerable: bool = False, **kwargs):
        self._vulnerable = vulnerable
        super().__init__(**kwargs)
