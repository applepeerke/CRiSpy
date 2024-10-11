# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : ValidatorPydantic
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-03-23 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.Plugins.Python.Validators.ValidatorBase import ValidatorBase
from src.gl.Const import APOSTROPHES, BLANK, EMPTY

PGM = 'ValidatorPydantic'


class ValidatorPydantic(ValidatorBase):

    def get_validator_field_name(self, line) -> str:
        """
        Get validator field name from the parsed class line
        """
        # E.g. '_validate_zip_code = validator("zip_code", ...)
        if '_validate_' not in line:
            return EMPTY

        # s = start position
        fs = 'validator('
        p = line.find(fs)
        if p == -1:
            return EMPTY
        s = p + len(fs)
        # Skip apostrophes
        while line[s] in APOSTROPHES:
            s += 1
        # e = End position
        e = s
        while e < len(line) \
                and line[e] not in APOSTROPHES \
                and line[e] not in (BLANK, ',', ')'):
            e += 1
        return line[s:e] if s < e else EMPTY
