# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.Plugins.Const import SANITIZED_BY_TYPE, SANITIZED_VIA_VALIDATOR
from src.core.Plugins.Python.Endpoints.FieldManagerBase import FieldManagerBase

PGM = 'FieldManagerBase'

# MarshMallow
LIST = 'List'
UNKNOWN = 'unknown'

marshmallow_string_fields = [
    'Field',
    'Raw',
    'List',
    'Tuple',
    'String',
    'Str',
    'Dict'
]


class MarshMallowFieldManager(FieldManagerBase):

    def __init__(self, parser, min_length=20):
        super().__init__(parser, min_length)

    def _is_sane_field(self, name, line) -> bool:
        self.get_field_type(line)
        if not self._field_type:
            return False

        if name == UNKNOWN or self._field_type not in marshmallow_string_fields:
            self._set_field_sane(line, SANITIZED_BY_TYPE)
            return True

        #  List field: substitute with child
        if self._field_type == LIST:
            field_type = self._parser.get_next_elem(delimiters=['(', ')'], LC=False, last_part_only=True)
            if field_type not in marshmallow_string_fields:
                self._set_field_sane(line, SANITIZED_BY_TYPE)
                return True
        #  Validation?
        if self._parser.find_and_set_pos('validate=', ignore_case=True):
            self._set_field_sane(line, SANITIZED_VIA_VALIDATOR)
            return True
