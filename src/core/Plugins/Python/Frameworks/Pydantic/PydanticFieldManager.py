# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : FieldManagerBase
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import SANITIZED_BY_TYPE, SANITIZED_VIA_REGEX
from src.core.Plugins.Python.Endpoints.FieldManagerBase import FieldManagerBase
from src.gl.Enums import Output
from src.gl.Validate import isName

# Pydantic
FIELD = 'Field'
LIST = 'List'
UUID = 'UUID'

UNKNOWN = 'unknown'
# Python
STR = 'str'
INT = 'int'
DATETIME = 'datetime'
BOOL = 'bool'

python_sane_types = ['int', 'long', 'float', 'bool', 'datetime', 'date', 'time']
pydantic_sane_types = ['Positiveint', 'FilePath', 'DirectoryPath', 'PastDate', 'FutureDate', 'EmailStr', 'NameEmail',
                       'HttpUrl', 'FileUrl', 'stricturl', 'UUID1', 'UUID2', 'UUID3', 'UUID4', 'UUID5',
                       'NegativeFloat', 'NegativeInt', 'PositiveFloat', 'PositiveInt',
                       'StrictInt', 'StrictFloat', 'StrictBool']


class PydanticFieldManager(FieldManagerBase):

    def __init__(self, parser=None, min_length=20):
        super().__init__(parser, min_length)

    def get_field(self, class_type, element: Element, line, line_no,
                  field_type=None, field_name=None, model_class=None) -> Field or None:

        self.get_field_type(line)
        if not self._field_type:
            return None

        # Find field name (must be valid name)
        name = None
        p = line.find(':')
        if p > -1:
            name = line[:p].strip()
            if not name or not isName(name):
                return None

        self._F = self._get_field_object(class_type, element, line, line_no, model_class, name, self._field_type)
        self._is_sane_field(name, line)
        return self._F

    def _is_sane_field(self, name, line) -> bool:
        if self._field_type in python_sane_types \
                or self._field_type in pydantic_sane_types \
                or '.' in self._field_type:  # Enum
            self._set_field_sane(line, SANITIZED_BY_TYPE)
            return True

        # Constant: assignment where source is not an object (example: "status_ok: str = "OK"")
        p = line.find('=')
        if p > -1 and line.find('(', p) == -1:
            self._set_field_sane(line, SANITIZED_BY_TYPE)
            return True

        #  List field: substitute with child
        if self._field_type == LIST:
            if not self._parser.find_and_set_pos('List[str]', set_line=line, ignore_case=True):
                self._set_field_sane(line, SANITIZED_BY_TYPE)
                return True

        # String field:
        if self._field_type == STR:
            # a. Try regex
            if self._parser.find_and_set_pos('regex=', set_line=line, ignore_case=True):
                self._set_field_sane(line, SANITIZED_VIA_REGEX)
                return True
            # b. Try max_length
            return self._evaluate_length(line, 'max_length=', ini_line=True)
        return False

    def get_field_type(self, line, LC=False, last_part_only=True):
        """
        Only "str" may be needed to find as assignee type in Pydantic.
        Example: "reference: Optional[str] = Field(max_length=50)"
        """
        self._field_type = None
        s = line.find(':')
        if s == -1:
            return
        e = line.find('=', s)
        if e == -1:
            e = line.find('#', s)
        if e == -1:
            e = len(line)
        # E.g. find "str" in "myField: Optional[List[str]] = None"
        if '[' in line:
            s = line.rfind('[')
            e = line.find(']', s)
        s += 1
        if e > s:
            self._field_type = line[s:e].strip()
        return

    @staticmethod
    def find_field_validators(scanner) -> list:
        validator_field_names = []
        search_string = '@validator'
        scanner.scan_dir(sp=SearchPattern(pattern=search_string, include_comment=False), output=Output.Object)

        for F in scanner.findings:
            p = F.line.find('(')
            if p == -1:
                continue

            q = F.line.find(')', p)
            if q > p > -1:
                validator_field_names.append(F.line[p + 1:q])
        return validator_field_names
