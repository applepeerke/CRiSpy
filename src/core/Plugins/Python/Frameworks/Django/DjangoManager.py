# ---------------------------------------------------------------------------------------------------------------------
# DjangoManager.py
#
# Author      : Peter Heijligers
# Description : Django manager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-05 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os

from src.core.DataLayer.SearchPattern import SearchPattern
from root_functions import slash
from src.core.Plugins.Python.Frameworks.FrameworkBase import FrameworkBase, HEADER_INPUT
from src.gl.Const import EMPTY
from src.gl.Enums import Output
from src.gl.Functions import find_files

PGM = 'DjangoManager'


class DjangoManager(FrameworkBase):

    @property
    def validator_field_names(self):
        return self._validator_field_names

    @property
    def settings_path(self):
        return self._django_settings_path

    @property
    def settings_module(self):
        return self._django_settings_module

    def __init__(self):
        super().__init__()
        self._django_settings_path = None
        self._django_settings_module = None
        self._validator_field_names = []

    def _start_specific(self):
        self._django_settings_path = None
        self._django_settings_module = None
        self._get_decorators()

    def _get_input_names(self):
        self._input_names = ['apiview', 'rest_framework.request', 'api_view']
        rows = self._get_rows('RestFramework_inputs', HEADER_INPUT)
        for row in rows:
            self._input_names.append(row[0])

    def get_settings(self) -> bool:
        """
        :return: are django settings found ?
        """
        # A. settings.py
        if self._session.input_dir:
            paths = find_files('settings.py', self._session.input_dir)
            if len(paths) > 1:
                paths = [path for path in paths if path.endswith(f'main{slash()}settings.py')]
            if paths:
                self._django_settings_path = paths[0]
                return True

        # B. settings module
        #   In wsgi.py, module "main.settings" may be a dir containing settings files:
        #   os.environ["DJANGO_SETTINGS_MODULE"] = "main.settings"
        # scanner = Scanner(self._session.input_dir, file_type='py' )
        self._scanner.scan_dir(
            sp=SearchPattern(pattern='DJANGO_SETTINGS_MODULE', include_comment=True),
            output=Output.Object)

        for F in self._scanner.findings:
            p = F.line.find('=')
            if -1 < p < len(F.line):
                sub_dir = F.line[p + 1:].strip(). \
                    replace('"', EMPTY).replace('\'', EMPTY).replace('.', slash())
                if os.path.isdir(f'{self._session.input_dir}{sub_dir}'):
                    self._django_settings_module = f'{self._session.input_dir}{sub_dir}'
                    return True

        if len(self._scanner.findings) > 0:
            return True
        return False

    def find_field_validators(self):
        search_string = ' validate_'
        self._scanner.scan_dir(sp=SearchPattern(pattern=search_string, include_comment=False), output=Output.Object)

        for F in self._scanner.findings:
            p = F.line.find(' def ')
            if p == -1:
                continue
            p = F.line.find(search_string) + len(search_string)
            q = F.line.find('(', p)
            if q > p > -1:
                self._validator_field_names.append(F.line[p:q])
