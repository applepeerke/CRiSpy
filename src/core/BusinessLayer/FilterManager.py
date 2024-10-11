#  ---------------------------------------------------------------------------------------------------------------------
# FilterManager.py
#
# Author      : Peter Heijligers
# Description : Return valid selections in a list.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-10-11 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os

from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.Config_constants import \
    CF_SPECIFIED_EXCLUDED_DIR_NAMES, CF_SPECIFIED_EXCLUDED_FILE_NAMES, CF_SPECIFIED_SANE_IF_PATTERN_IN
from src.gl.BusinessLayer.CsvManager import CsvManager as Data_Manager
from src.gl.Const import ASTERISK, EMPTY
from src.gl.Functions import path_leaf


class FilterManager(object):

    @property
    def debug_path(self):
        return f'{self._debug_dir}{self._debug_filename}' if self._debug_dir and self._debug_filename else None

    @property
    def extensions(self):
        return self._extensions

    @property
    def ignore_path_parts(self):
        return self._ignore_path_parts

    @property
    def ignore_path_parts_starting_with(self):
        return self._ignore_path_parts_starting_with

    @property
    def ignore_path_parts_ending_with(self):
        return self._ignore_path_parts_ending_with

    @property
    def ignore_file_names(self):
        return self._ignore_file_names

    @property
    def sane_if_pattern_in_verb(self):
        return self._sane_if_pattern_in_verb

    @property
    def ignore_source_lines_start(self):
        return self._ignore_source_lines_start

    @property
    def extension_excludes(self):
        return self._extension_excludes

    @property
    def path_part_excludes(self):
        return self._path_part_excludes

    @debug_path.setter
    def debug_path(self, value):
        self._debug_dir, self._debug_filename = \
            os.path.split(value) if value and os.path.isfile(value) else None, None

    @ignore_source_lines_start.setter
    def ignore_source_lines_start(self, value):
        self._ignore_source_lines_start = value

    def __init__(self):
        self._data_manager = Data_Manager()
        self._data_manager.file_name = 'Filters.csv'
        self._extensions = None
        self._ignore_path_parts = set()
        self._ignore_path_parts_starting_with = set()
        self._ignore_path_parts_ending_with = set()
        self._ignore_file_names = set()
        self._sane_if_pattern_in_verb = set()
        self._ignore_source_lines_start = set()
        self._extension_excludes = set()
        self._path_part_excludes = set()
        self._is_filter_set = False
        self._debug_dir = None
        self._debug_filename = None

    def set_filter(self):
        CFM = ConfigManager()
        self._is_filter_set = True
        if not self.extensions:
            self._extensions = self.get_column(2, 'FileExt', 'Ignore')
            self._ignore_path_parts = set(map(str.lower, self.get_column(2, 'PathPart', 'Contains')))
            self._ignore_path_parts_starting_with = set(map(str.lower, self.get_column(
                2, 'PathPart', 'StartsWith')))
            self._ignore_path_parts_ending_with = set(map(str.lower, self.get_column(
                2, 'PathPart', 'EndsWith')))
            self._ignore_file_names = set(map(str.lower, self.get_column(2, 'FileName', 'Ignore')))
            self._ignore_source_lines_start = set(map(str.lower, self.get_column(2, 'SourceLine', 'StartsWith')))

        # Add the specified (project- or CRiSp call-dependent) path parts
        specified_excluded = CFM.get_config_item(CF_SPECIFIED_EXCLUDED_DIR_NAMES)
        if specified_excluded:
            [self._add_excluded_path_parts(i) for i in specified_excluded.split(',')]
        specified_excluded = CFM.get_config_item(CF_SPECIFIED_EXCLUDED_FILE_NAMES)
        if specified_excluded:
            [self._add_excluded_path_parts(i) for i in specified_excluded.split(',')]

        # Add the specified (project- or CRiSp call-dependent) pattern sanitizers
        specified_sane_if_pattern_in = CFM.get_config_item(CF_SPECIFIED_SANE_IF_PATTERN_IN)
        if specified_sane_if_pattern_in:
            [self._sane_if_pattern_in_verb.add(i.lower().strip()) for i in specified_sane_if_pattern_in.split(',')]
        return

    def _add_excluded_path_parts(self, part):
        part = part.lower().strip() if part else None
        if not part:
            return
        if part.startswith(ASTERISK) and part.endswith(ASTERISK) and len(part) > 2:
            self._ignore_path_parts.add(part[1:-1])
        elif part.startswith(ASTERISK):
            self._ignore_path_parts_ending_with.add(part[1:])
        elif part.endswith(ASTERISK):
            self._ignore_path_parts_starting_with.add(part[:-1])
        else:
            self._ignore_path_parts.add(part)

    def is_excluded(self, file_name=None, ext=None, path=None, source_line_start=None) -> bool:
        # Extension
        if ext:
            ext = ext.lower()
            if ext in self._extensions:
                return True
            # Extensions like ".min.js"
            if self._exclude_ext(file_name):
                return True

        # File name
        if self._exclude_file_name(file_name):
            return True

        # Path
        if path:
            path = path.lower()
            _, leaf = path_leaf(path)
            if leaf:
                file_name, ext = os.path.splitext(leaf)
                if self._exclude_ext(leaf) or self._exclude_file_name(file_name):
                    return True
                for i in self.ignore_path_parts:
                    if i in path:
                        return True
                for i in self.ignore_path_parts_starting_with:
                    if i in path:
                        path_stub, leaf = path_leaf(path)
                        while leaf != EMPTY and not leaf.startswith(i):
                            path_stub, leaf = path_leaf(path_stub)
                        if leaf and leaf.startswith(i):
                            return True
                for i in self.ignore_path_parts_ending_with:
                    if i in path:
                        path_stub, leaf = path_leaf(path)
                        while leaf != EMPTY and not leaf.endswith(i):
                            path_stub, leaf = path_leaf(path_stub)
                        if leaf and leaf.endswith(i):
                            return True

        # Source line start
        if source_line_start:
            for i in self.ignore_source_lines_start:
                if source_line_start.lower().startswith(i):
                    return True
        return False

    def _exclude_ext(self, base_name) -> bool:
        if not base_name:
            return False
        # Also extensions like ".min.js"
        return any(base_name.lower().endswith(i) for i in self._extensions)

    def _exclude_file_name(self, file_name) -> bool:
        if not file_name:
            return False
        file_name = file_name.lower()
        if file_name in self._ignore_file_names:
            return True
        for i in self._ignore_path_parts:
            if i in file_name:
                return True
        for i in self._ignore_path_parts_starting_with:
            if file_name.startswith(i):
                return True
        for i in self._ignore_path_parts_ending_with:
            if file_name.endswith(i):
                return True
        return False

    def _get_rows(self, type_name=EMPTY, subtype=EMPTY) -> list:
        rows = self._data_manager.get_rows(where={0: type_name, 1: subtype})
        return rows

    def get_column(self, column, type_name=EMPTY, subtype=EMPTY) -> list:
        """
        Return a column for a type|subtype combination
        :param column: int - Column number to return
        :param type_name: Extension type (default = all)
        :param subtype: Extension subtype (default = all)
        :return: List. Optionally filtered column.
        """
        extensions = []
        rows = self._get_rows(type_name, subtype)
        for row in rows:
            extensions.append(row[column])
        return extensions

    def is_filtered(self, column, type_name=EMPTY, subtype=EMPTY) -> list:
        """
        Return a column for a type|subtype combination
        :param column: int - Column number to return
        :param type_name: Extension type (default = all)
        :param subtype: Extension subtype (default = all)
        :return: List. Optionally filtered column.
        """
        extensions = []
        rows = self._get_rows(type_name, subtype)
        for row in rows:
            extensions.append(row[column])
        return extensions

    def is_valid_filename(self, filename, use_filter=True) -> bool:
        # Debug mode
        if self._debug_filename:
            return True if filename == self._debug_filename else False

        # Normal mode
        if not use_filter or not self._is_filter_set:
            return True

        file_name_lower = filename.lower()

        # Filter file names
        for ignore in self._ignore_file_names:
            # Start "*":
            if ignore.startswith('*'):
                # Start and end "*".
                # E.g. "*example*": "example.py" is end of "params.example.py"
                if ignore.endswith('*') and ignore[1:-1] in file_name_lower:
                    return False
                # Start "*" only.
                # E.g. "*example.py": "example.py" in "params.example.py"
                elif file_name_lower.endswith(ignore[1:]):
                    return False
            # End "*".
            # E.g. "params.example*": "params.example" is start of "params.example.py"
            elif ignore.endswith('*') and file_name_lower.startswith(ignore[:-1]):
                return False
            # Normal, e.g. "params.example.py" == "params.example.py"
            elif ignore == file_name_lower:
                return False

        # Filter parts like "test" and "mock"
        for ignore_path_part in self._ignore_path_parts:
            if ignore_path_part in file_name_lower:
                self._path_part_excludes.add(ignore_path_part)
                return False

        # Filter file extensions like ".jpg" and ".diff.txt"
        for extension in self._extensions:
            if file_name_lower.endswith(extension):
                self._extension_excludes.add(extension)
                return False

        for ignore_part in self._ignore_path_parts_starting_with:
            if file_name_lower.startswith(ignore_part):
                self._path_part_excludes.add(ignore_part)
                return False

        for ignore_part in self._ignore_path_parts_ending_with:
            if file_name_lower.endswith(ignore_part):
                self._path_part_excludes.add(ignore_part)
                return False
        return True

    def is_valid_dir(self, basedir, path, use_filter=True):
        if not use_filter:
            return True

        # Debug mode
        if self._debug_dir:
            return True if path.startswith(self._debug_dir) else False

        # Filter parts like "test" and "mock",
        find_string = basedir[:len(basedir) - 1]
        rest = path.replace(find_string, "").lower()
        if rest != EMPTY:
            for ignore_path_part in self._ignore_path_parts:
                if ignore_path_part in rest:
                    return False
            for ignore_part in self._ignore_path_parts_starting_with:
                if rest[1:].startswith(ignore_part):
                    return False
            for ignore_part in self._ignore_path_parts_ending_with:
                if rest.endswith(ignore_part):
                    return False
        return True
