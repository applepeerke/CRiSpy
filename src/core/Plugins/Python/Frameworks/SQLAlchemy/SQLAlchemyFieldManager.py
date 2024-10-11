# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.Plugins.Const import SANITIZED_BY_TYPE
from src.core.Plugins.Python.Endpoints.FieldManagerBase import FieldManagerBase

PGM = 'SQLAlchemyFieldManager'

# - General
STRING = 'String'
UNICODE = 'Unicode'
TEXT = 'Text'
UNICODETEXT = 'UnicodeTex'
# - SQL
CHAR = 'CHAR'
CLOB = 'CLOB'
JSON = 'JSON'
NCHAR = 'NCHAR'
NVARCHAR = 'NVARCHAR'
VARCHAR = 'VARCHAR'

sqlalchemy_string_fields = {
    STRING: 'string',
    UNICODE: 'unicode',
    TEXT: 'text',
    UNICODETEXT: 'unicodetext',
    # SQL
    CHAR: 'char',
    CLOB: 'clob',
    JSON: 'JSON',  # vulnerable when evaluated
    NCHAR: 'NCHAR',
    NVARCHAR: 'NVARCHAR',
    VARCHAR: 'VARCHAR',
}


class SQLAlchemyFieldManager(FieldManagerBase):

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
        if self._field_type not in sqlalchemy_string_fields:
            self._set_field_sane(line, SANITIZED_BY_TYPE)
            return True

        # String field: Try length
        return self._evaluate_length(line, 'length=')

    def _substitute_field_type(self, LC, last_part_only):
        # First the Column type must be skipped.
        delimiters = ['(', ',', ')']
        if self._field_type == 'Column':
            self._field_type = self._parser.get_next_elem(delimiters=delimiters, LC=LC, last_part_only=last_part_only)
