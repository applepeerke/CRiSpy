# ---------------------------------------------------------------------------------------------------------------------
# ClassManager.py
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-02-13 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
import fnmatch

import os

from src.core.BusinessLayer.FilterManager import FilterManager
from src.core.Plugins.Const import CLASS
from src.gl.BusinessLayer.TimeManager import time_exec
from src.gl.Const import EMPTY, UNKNOWN
from src.gl.Functions import strip_bytes_and_crlf, loop_increment
from src.gl.Parse.Parser_Python import Parser_Python

parser = Parser_Python()
filter_manager = FilterManager()

PGM = 'ClassManager'


class ClassManager(object):

    @property
    def class_supers_dict(self):
        return self._class_super_dict

    @property
    def class_descendants_dict(self):
        return self._class_descendants_dict

    def __init__(self):
        self._class_super_dict = {}
        self._class_descendants_dict = {}
        self._base_dir = None
        self._exclude_start_with = []

    def scan_dir(self, base_dir) -> bool:
        filter_manager.set_filter()
        self._base_dir = base_dir
        for file_path in self._find_files("*.py", base_dir):
            self._scan_source(file_path)
        return True

    def _scan_source(self, file_path):
        if os.path.basename(file_path) == '.DS_Store':
            return

        # Open file for reading
        fo = open(file_path, 'rb')

        # Read the first line from the file, convert binary to string (utf-8)
        line = str(fo.readline())

        # Loop until EOF
        while line != 'b\'\'':
            line = strip_bytes_and_crlf(line)
            line = line.lstrip()
            if line and line.lower().startswith(CLASS):
                if parser.find_and_set_pos(CLASS, set_line=line, just_after=True, ignore_case=True):
                    class_name = parser.get_next_elem(delimiters=['('], LC=False)
                    super_names = parser.get_next_elems(delimiters=[')'], LC=False, last_part_only=True)
                    if class_name and super_names:
                        # class: add all supers
                        class_key = self.get_key(file_path, class_name)
                        self._class_super_dict[class_key] = super_names
                        # all supers: add class as descendant
                        # Todo: for now accept unique super names (without paths) only, otherwise error
                        for s in super_names:
                            if s in self._class_descendants_dict:
                                self._class_descendants_dict[s].append(class_name)
                            else:
                                self._class_descendants_dict[s] = [class_name]
            # Read next line
            line = str(fo.readline())

        # Close the file
        fo.close()

    def get_key(self, path, class_name):
        if not path or not class_name:
            return UNKNOWN
        return f'{path.replace(self._base_dir, EMPTY)}.{class_name}'

    @time_exec
    def add_descendants(self, class_name, exclude_start_with: list) -> list:
        self._exclude_start_with = exclude_start_with
        # a. class_list = class name + descendants for the class
        # b. for every class_list member, get the lower descendants
        # c. For every new lower descendant, that is not yet processed, get the lower descendants
        # d. Repeat c until no unprocessed descendant is left.
        if not class_name:
            return []

        class_list = self._filtered(
            self._class_descendants_dict[class_name] if class_name in self._class_descendants_dict else [class_name])
        processed_dict = {s: False for s in class_list}

        while loop_increment(f'{__name__}'):
            new_classes = []
            if False not in processed_dict.values():
                break
            for hs, processed in processed_dict.items():
                processed_dict[hs] = True
                if hs in self._class_descendants_dict:
                    # Get recursive  descendants
                    descendants = self._filtered(self.class_descendants_dict[hs])
                    for h in descendants:
                        if h not in processed_dict:
                            # Add to super tree list
                            class_list.append(h)
                            new_classes.append(h)
            for h in new_classes:
                processed_dict[h] = False
        return class_list

    def _filtered(self, names):
        if self._exclude_start_with:
            for e in self._exclude_start_with:
                names = [n for n in names if not n.startswith(e)]
        return names

    @staticmethod
    def _find_files(file_type, basedir):
        """
        Return all file paths matching the specified file type in the specified base directory (recursively).
        """
        for path, dirs, files in os.walk(os.path.abspath(basedir)):
            if filter_manager.is_valid_dir(basedir, path):
                for filename in fnmatch.filter(files, file_type):
                    if filter_manager.is_valid_filename(filename, use_filter=True):
                        yield os.path.join(path, filename)
