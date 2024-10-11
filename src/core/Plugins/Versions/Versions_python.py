# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_Python.py
#
# Author      : Peter Heijligers
# Description : Python plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2023-03-13 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.Functions.Functions import strip_line
from src.core.Plugins.Versions.VersionsBase import VersionsBase
from src.gl.Const import EMPTY
from src.gl.Validate import isFilename, isVersion


class Versions_python(VersionsBase):

    def __init__(self, scanner, cli_mode=False):
        super().__init__(scanner, cli_mode)
        self._filename = None

    def _add_versions(self, filename, path):
        self._filename = filename
        # Get the file
        with open(path) as file:
            lines = file.readlines()
        # Get data from lines
        self._package_versions = {}
        self._mode, self._name, self._version = None, None, None
        if self._filename == 'poetry.lock':
            [self._add_version_poetry(line) for line in lines]
        else:
            [self._add_version_requirements(line) for line in lines]
        # Dictionary output
        self._versions_by_path[path] = self._package_versions

    def _add_version_requirements(self, line):
        names = strip_line(line).split('==')
        if len(names) == 2 and isFilename(names[0]) and isVersion(names[1]):
            self._package_versions[names[0]] = names[1]

    def _add_version_poetry(self, line):
        """ poetry.lock"""
        if '[[package]]' in line:
            self._mode = 'name'
        elif self._mode == 'name':
            if 'name' in line:
                self._name = self._get_assignee(line)
                self._mode = 'version'
        elif self._mode == 'version':
            if 'version' in line:
                version = self._get_assignee(line)
                if isFilename(self._name) and isVersion(version):
                    self._package_versions[self._name] = version
            self._mode, self._name = None, None
        else:
            self._mode, self._name = None, None

    @staticmethod
    def _get_assignee(line) -> str or None:
        assignee = None
        names = strip_line(line).split('=')
        if len(names) == 2:
            assignee = names[1].strip().replace('"', EMPTY).replace("'", EMPTY)
        return assignee
