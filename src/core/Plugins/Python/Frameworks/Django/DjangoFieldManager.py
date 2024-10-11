# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.Plugins.Const import SANITIZED_BY_TYPE, SANITIZED_VIA_VALIDATOR, SANITIZED_VIA_ALLOW_LIST
from src.core.Plugins.Python.Endpoints.FieldManagerBase import FieldManagerBase

PGM = 'DjangoFieldManager'

CHARFIELD = 'CharField'
TEXTFIELD = 'TextField'
FILEFIELD = 'FileField'
LISTFIELD = 'ListField'
DICTFIELD = 'DictField'
# URLFIELD = 'URLField'
# FILEPATHFIELD = 'FilePathField'
# EMAILFIELD = 'EmailField'

# EmailField is also sane, it is tested on characters and length (max 64)
django_string_fields = {
    CHARFIELD: 'charfield',
    TEXTFIELD: 'textfield',
    FILEFIELD: 'filefield',
    LISTFIELD: 'listfield',
    DICTFIELD: 'dictfield'
}


class DjangoFieldManager(FieldManagerBase):

    def __init__(self, parser, min_length=20):
        super().__init__(parser, min_length)

    def _add_sanitizer_custom_types(self, element):
        """ Remember field types that are sanitizers """
        # Keep special fields types ( like serializer classes ) in a set with the input serializer
        if not self._field_type.endswith('Field'):
            if element.class_name in self._sanitizer_specialTypes:
                self._sanitizer_specialTypes[element.class_name].add(self._field_type)
            else:
                self._sanitizer_specialTypes[element.class_name] = {self._field_type}

    def _is_sane_field(self, name, line) -> bool:
        self.get_field_type(line)
        if not self._field_type:
            return False

        if self._field_type not in django_string_fields:
            self._set_field_sane(line, SANITIZED_BY_TYPE)
            return True

        #  List field: substitute with child
        if self._field_type in (LISTFIELD, DICTFIELD):
            if self._parser.find_and_set_pos('child=', ignore_case=True):
                _ = self._parser.get_next_elem(delimiters=['='])
                field_type = self._parser.get_next_elem(delimiters=['(', ')'], LC=False, last_part_only=True)
                if field_type not in django_string_fields:
                    self._set_field_sane(line, SANITIZED_BY_TYPE)
                    return True

        # String field:
        if self._field_type in (CHARFIELD, TEXTFIELD):
            # a. Try validator ('validator_field_names', 'validators='
            if self._parser.find_and_set_pos('validator', ignore_case=True):
                self._set_field_sane(line, SANITIZED_VIA_VALIDATOR)
                return True
            # b. Try choices
            if self._parser.find_and_set_pos('choices=', ignore_case=True):
                self._set_field_sane(line, SANITIZED_VIA_ALLOW_LIST)
                return True
            # c. Try max_length
            return self._evaluate_length(line, 'max_length=')
        return False
