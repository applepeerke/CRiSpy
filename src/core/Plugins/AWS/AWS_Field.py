# ---------------------------------------------------------------------------------------------------------------------
# AWS_Field.py
#
# Author      : Peter Heijligers
# Description : AWS Object attribute
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-05-04 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Field import Field
from src.core.Plugins.AWS.Enums import SchemaItem
from src.core.Plugins.Const import SANITIZED_BY_TYPE, SANITIZED_BY_LENGTH, SANITIZED_VIA_REGEX
from src.gl.Const import EMPTY
from src.gl.Validate import isInt


class AWS_Field(Field):

    @property
    def value(self):
        return self._name

    @property
    def max_length(self):
        return self._max_length

    @property
    def pattern(self):
        return self._pattern

    def __init__(self, context_type, field_type, name, value=EMPTY, length=0, parent_name=EMPTY, max_length=0,
                 pattern=EMPTY, element: Element = None):
        super().__init__(context_type, element, parent_name, field_type, length=max_length)
        self._context_type = context_type
        self._name = name
        self._value = value
        self._field_type = field_type
        self._length = length
        self._parent_name = parent_name
        self._max_length = max_length
        self._pattern = pattern
        self._vulnerable = True
        self._title = EMPTY
        self._element = element

        # Reference
        if self._name == SchemaItem.Ref:
            self._field_type = self._value

        self._set_vulnerable()

    def _set_vulnerable(self):
        if self._field_type in ('number', 'integer', 'float', SchemaItem.Enum):
            self._title = f'{SANITIZED_BY_TYPE} validation detected.'
            self._vulnerable = False
        elif isInt(self._max_length) and 0 < int(self._max_length) <= 20:
            self._title = f'{SANITIZED_BY_LENGTH} validation detected.'
            self._vulnerable = False
        elif self._pattern:
            self._title = f'{SANITIZED_VIA_REGEX} validation detected.'
            self._vulnerable = False
