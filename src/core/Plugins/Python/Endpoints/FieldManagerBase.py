# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.CodeBase.Element import Element
from src.core.Plugins.Const import SANITIZED_BY_LENGTH
from src.gl.Const import BLANK
from src.gl.Validate import isInt, isAlpha, isName, isBool

PGM = 'FieldManagerBase'


class FieldManagerBase(object):

    @property
    def messages(self):
        return self._messages

    @property
    def special_type_parents(self):
        return self._specialType_parent_dict

    def __init__(self, parser, min_length=20):
        self._parser = parser
        self._min_length = min_length
        self._messages = []
        self._F = None
        self._first_parm = None
        self._sanitizer_specialTypes = {}
        self._specialType_parent_dict = {}
        self._field_type = None

    def get_field(self, class_type, element: Element, line, line_no,
                  field_type=None, field_name=None, model_class=None) -> Field or None:

        # Find field type (must be valid name)
        self.get_field_type(line) if not field_type else field_type
        if not self._field_type:
            return None

        # Optionally add field types that are sanitizers.
        self._add_sanitizer_custom_types(element)

        # Find field name (must be valid name)
        name = self._get_assigned_variable(line) if not field_name else field_name
        if not name:
            return None

        self._F = self._get_field_object(class_type, element, line, line_no, model_class, name)
        self._is_sane_field(name, line)
        return self._F

    def get_field_type(self, line, LC=False, last_part_only=True):
        delimiters = ['(']
        self._field_type = self._get_assigner(line, delimiters, LC, last_part_only=last_part_only)

        # In SQLAlchemy, first the Column type must be skipped.
        self._substitute_field_type(LC, last_part_only)

        # Field type must be a valid name like "CharField"
        if not self._field_type or not isAlpha(self._field_type) or isBool(self._field_type):
            self._field_type = None
            return

        # Remember 1st parameter, it may be a int defining the length (Django, SqlAlchemy).
        self._first_parm = self._parser.get_next_elem(delimiters=delimiters)

    def get_specialType_parents(self, sanitizer_name) -> list:
        if not self._sanitizer_specialTypes:
            return []

        # Do it once
        result = []
        if not self._specialType_parent_dict:
            for parent_sanitizer, special_serializers in self._sanitizer_specialTypes.items():
                for s in special_serializers:
                    if s not in self._specialType_parent_dict:
                        self._specialType_parent_dict[s] = {parent_sanitizer}
                    else:
                        self._specialType_parent_dict[s].add(parent_sanitizer)
        if sanitizer_name in self._specialType_parent_dict:
            result = list(self._specialType_parent_dict[sanitizer_name])
        return result

    def is_sane_field(self, line) -> bool:
        pass

    def _is_sane_field(self, name, line) -> bool:
        pass

    def _substitute_field_type(self, LC, last_part_only):
        pass

    def _get_field_object(self, class_type, element: Element, line, line_no, model_class, name, field_type=None
                          ) -> Field:
        field_type = field_type or self._field_type
        string_field_type_element = Element(
            path=element.path,
            line_no=line_no,
            pos=self._parser.pos,
            name=name,
            line=line)

        return Field(
            context_type=class_type,
            title=f'Possible injection vulnerability in {field_type} attribute',
            element=string_field_type_element,
            parent_name=element.name,
            vulnerable=True,
            field_type=field_type,
            model_class=model_class
        )

    def _evaluate_length(self, line, find_string, ini_line=False) -> bool:
        elem = '0'
        set_line = line if ini_line else None
        if self._parser.find_and_set_pos(
                find_string, set_line=set_line, ini_pos=True, just_after=True, ignore_case=True):
            elem = self._parser.get_next_elem(delimiters=[BLANK, ',', ')'])
        elif self._first_parm and isInt(self._first_parm):  # 1st parameter may be the length without a keyword
            elem = self._first_parm
        self._F.length = int(elem) if isInt(elem) else 0

        if 0 < self._F.length <= self._min_length:
            self._set_field_sane(line, SANITIZED_BY_LENGTH)
            return True
        return False

    def _set_field_sane(self, line, sani_type):
        if self._F and self._F.element.name and line.find(self._F.element.name) > -1:
            self._F = self.set_field_sane(self._F, sani_type)

    @staticmethod
    def set_field_sane(field, sani_type, suffix=True) -> Field:
        field.title = f'{sani_type} validation detected.' if suffix else sani_type
        field.vulnerable = False
        return field

    def _get_assigner(self, line, delimiters, LC=False, last_part_only=False) -> str or None:
        self._parser.line = line
        self._parser.find_and_set_pos('=', just_after=True)
        assigner = self._parser.get_next_elem(delimiters=delimiters, LC=LC, last_part_only=last_part_only)
        return assigner if isName(assigner) else None

    def _get_assigned_variable(self, line):
        """
        Example: "assignment_variable = assigner"
        """
        var = None
        self._parser.line = line
        if self._parser.find_and_set_pos('=', just_before=True):
            var = self._parser.get_prv_elem(LC=False)
            if self._parser.find_and_set_pos(':', just_before=True):
                var = self._parser.get_prv_elem(LC=False)
        return var if var and isName(var) else None

    def _add_sanitizer_custom_types(self, element):
        pass
