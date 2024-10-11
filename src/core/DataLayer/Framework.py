# ---------------------------------------------------------------------------------------------------------------------
# Framework.py
#
# Author      : Peter Heijligers
# Description : Framework
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-17 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import FrameworkName

DB_METHODS = {
    FrameworkName.Unknown: ('insert', 'update', 'delete', 'save'),
    FrameworkName.Django: ('save', 'create'),
    FrameworkName.Flask: ('write_results',),
    FrameworkName.SQLAlchemy: ('insert', 'update', 'delete'),
}


class Framework(object):

    @property
    def name(self):
        return self._name

    @property
    def scanner(self):
        return self._scanner

    @property
    def findings(self):
        return self._findings

    @property
    def models(self):
        return self._models

    def __init__(self,
                 name,
                 models=None,
                 scanner=None,
                 ):
        self._name = name
        self._models = models or {}
        self._scanner = scanner  # Per file type like '.py'
        self._findings = self._scanner.findings if self._scanner else []
