# ---------------------------------------------------------------------------------------------------------------------
# Django_source_analyzer.py
#
# Author      : Peter Heijligers
# Description : Python validation vulnerabilities
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-01-22 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from abc import ABC

from src.core.Plugins.Const import CLASS, DEF, METHOD, SPECIAL_TYPES, MODULE
from src.core.Plugins.Python.Frameworks.Django.Constants import DJANGO_SERIALIZER_CLASS
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import MAX_LOOP_COUNT, BLANK, EMPTY
from src.gl.Enums import MessageSeverity
from src.gl.Message import Message
from src.gl.Parse.Parser_Python import Parser_Python
from src.gl.Validate import isName

PGM = 'DjangoParser'
FIRST_ELEMS_PY = {METHOD: ['def', 'async'], CLASS: ['class']}


class DjangoParser(Parser_Python, ABC):

    @property
    def messages(self):
        return self._messages

    def __init__(self):
        super().__init__()
        self._var_dict = {}
        self._session = Session()
        self._messages = []

        self._loop_count = 0
        self._mode = MODULE

    def initialize(self):
        """ Parse the view that contains the api methods."""
        self._mode = MODULE
        self._var_dict[self._mode] = {}

    def get_first_elem(self, line, mode=METHOD, dft=None):
        result = dft
        line_stripped = line.lstrip()
        p = line_stripped.find(BLANK)
        if p == -1 or line_stripped[:p].lower() not in FIRST_ELEMS_PY[mode]:
            return result
        find_str = DEF if mode == METHOD else CLASS
        if self.find_and_set_pos(find_str, set_line=line, just_after=True):
            delimiters = ['(']
            result = self.get_next_elem(delimiters, LC=False)
            if result:
                self._mode = mode
                self._var_dict[self._mode] = {}  # Found: Initialize this level
        return result

    def set_assignment(self, line):
        """
        Remember last variable name (overwrite duplicates).
        """
        target = self._get_assignment_target(line)
        if not target:
            return

        # Get the most specific name.
        source = None
        special_type = False
        ignore = '.'
        self._loop_count = 0
        while ignore == '.':
            source = self.get_next_elem(delimiters=['(', '.'], LC=False)
            if not special_type:
                special_type = source in SPECIAL_TYPES
            ignore = self.delimiter
            if not self._valid_loop():
                break

        if not source:
            return
        # Ok!

        self._var_dict[self._mode][target] = source

    def get_assignment_source_by_find_string(self, find_string, line) -> str:
        """  Example: "required_scope" assignment  """
        p = line.find(find_string)
        if p == -1 or not self._get_assignment_target(line):
            return EMPTY
        return self.get_next_elem(LC=False)

    def _get_assignment_target(self, line) -> str:
        if '=' not in line:
            return EMPTY

        self.set_line(line)
        # Get 1st element
        target = self.get_next_elem(delimiters=['=', '(', '[', '{'], LC=False)
        if not target:
            return EMPTY

        # Operator must be "="
        operator = self.delimiter
        if operator == BLANK:
            operator = self.get_next_elem()
        if operator != '=':
            return EMPTY
        return target

    def _valid_loop(self) -> bool:
        self._loop_count += 1
        if self._loop_count > MAX_LOOP_COUNT:
            self._messages.append(Message(f"{PGM}: ERROR: MAX LOOP COUNT REACHED!!!!'", MessageSeverity.Error))
            return False
        return True

    def get_sanitizer_name(self, line) -> str:
        """
        In the line, search for ".is_valid."
        When found, the corresponding type should match with the type of one of the latest detected variable names.
        (Think of multiple endpoints in 1 file with the same local var names).
        """

        # For generic Django classes "serializer_class" is the sanitizer.
        if line.find(DJANGO_SERIALIZER_CLASS) != -1 \
                or not self.find_and_set_pos('.is_valid(', set_line=line):
            return EMPTY

        # .is_valid is found. Convert var-name to serializer type.
        var_name = self.get_prv_elem(LC=False, skip_first=['.'])
        name = self._get_type_from_var_name(var_name)

        # Add the serializer name.
        return name if name and isName(name) else EMPTY

    def _get_type_from_var_name(self, var_name) -> str or None:
        """
        Get the variable value from specific to general level
        """
        if not var_name:
            return None

        self._var_name = var_name

        if self._mode == METHOD:
            self._set_var_name_from_METHOD()
        elif self._mode == CLASS:
            self._set_var_name_from_CLASS()
        elif self._mode == MODULE:
            self._set_var_name_from_MODULE()

        return self._var_name

    def _set_var_name_from_METHOD(self) -> bool:
        if METHOD in self._var_dict and self._var_name in self._var_dict[METHOD]:
            self._var_name = self._var_dict[METHOD][self._var_name]
            # After Method substitution, try Class (and Module) too
            self._set_var_name_from_CLASS()
        return self._var_name is not None

    def _set_var_name_from_CLASS(self) -> bool:
        # Class
        if CLASS in self._var_dict and self._var_name in self._var_dict[CLASS]:
            self._var_name = self._var_dict[CLASS][self._var_name]
        else:
            # Not in Class: try Module
            self._set_var_name_from_MODULE()
        return self._var_name is not None

    def _set_var_name_from_MODULE(self) -> bool:
        if MODULE in self._var_dict and self._var_name in self._var_dict[MODULE]:
            self._var_name = self._var_dict[MODULE][self._var_name]
            return self._var_name is not None
