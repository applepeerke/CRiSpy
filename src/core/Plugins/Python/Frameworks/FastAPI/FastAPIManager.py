# ---------------------------------------------------------------------------------------------------------------------
# FastAPIManager.py
#
# Author      : Peter Heijligers
# Description : RestFramework manager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-08-18 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Python.Frameworks.FrameworkBase import FrameworkBase
from src.gl.Enums import Output
from src.gl.Validate import isName

PGM = 'FastAPIManager'


class FastAPIManager(FrameworkBase):

    def __init__(self):
        super().__init__()

    def _start_specific(self):
        self._input_names = ['@router.', 'APIRouter(']
        self._extend_input_names()

    def _extend_input_names(self) -> bool:
        input_names = set(self._input_names)
        # Get synonyms
        router_names = self._get_assignment_targets('APIRouter(')
        [input_names.add(router_name) for router_name in router_names]
        self._input_names = list(input_names)
        return True if router_names else False

    def _get_assignment_targets(self, pattern) -> list:
        self._scanner.scan_dir(
            sp=SearchPattern(pattern=pattern, include_comment=False),
            output=Output.Object)
        return list({self._get_router_decorator(F.line) for F in self._scanner.findings})

    @staticmethod
    def _get_router_decorator(line) -> str:
        """ E.g. "public_router = ApiRouter(...)" will be used in the endpoint as "@router.get(...)"""
        p = line.find('=')
        target = line[:p].strip()
        if isName(target):
            return f'@{target}.'
