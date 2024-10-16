from typing import List

from pydantic import BaseModel


class LineModel(BaseModel):
    lines: List[str]
