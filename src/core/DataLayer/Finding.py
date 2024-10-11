# ---------------------------------------------------------------------------------------------------------------------
# Finding.py
#
# Author      : Peter Heijligers
# Description : Validation functions
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-10-22 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os

from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Functions.Functions import slash
from src.gl.Const import EMPTY
from src.gl.Enums import MessageSeverity
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message


class Finding(object):

    @property
    def dir_name(self):
        return self._dir_name

    @property
    def file_name(self):
        return self._file_name

    @property
    def line_no(self):
        return self._line_no

    @property
    def start_pos(self):
        return self._start_pos

    @property
    def end_pos(self):
        return self._end_pos

    @property
    def finding(self):
        return self._finding

    @property
    def path(self):
        return self._path

    @property
    def line(self):
        return self._line

    @property
    def base_dir(self):
        return self._base_dir

    @property
    def search_pattern(self):
        return self._search_pattern

    @property
    def truncated_dir(self):
        return self._truncated_dir

    @property
    def formatted_line(self):
        return self._formatted_line

    @property
    def file_ext(self):
        return self._file_ext

    def __init__(self,
                 file_name=EMPTY,
                 line_no: int = 0,
                 start_pos: int = 0,
                 end_pos: int = 0,
                 finding=None,
                 dir_name=EMPTY,
                 path=EMPTY,
                 line=EMPTY,
                 base_dir=EMPTY,
                 search_pattern: SearchPattern = None):
        self._dir_name = dir_name
        self._file_name = file_name
        self._line_no = line_no
        self._start_pos = start_pos
        self._end_pos = end_pos
        self._finding = self._get_finding(finding, start_pos, end_pos)
        if file_name and dir_name and not path:
            path = dir_name + file_name
        self._path = path
        self._line = line
        self._base_dir = base_dir
        self._file_ext = EMPTY
        self._search_pattern = search_pattern
        self._truncated_dir = EMPTY
        self._formatted_line = EMPTY

        # For scanner
        line_no_str = str(line_no)

        if path:
            file_dir = os.path.dirname(path)
            file_name_ext = os.path.basename(path)
            _, self._file_ext = os.path.splitext(file_name_ext)
            if not self._file_name:
                self._file_name = file_name_ext
            if base_dir:
                self._truncated_dir = file_dir.replace(base_dir, EMPTY)
                # Support files directly in the root
                if self._truncated_dir == file_dir:
                    file_dir = f'{file_dir}{slash()}'
                    self._truncated_dir = file_dir.replace(base_dir, EMPTY)
                self._formatted_line = f'{path.replace(base_dir, EMPTY)}:{line_no_str}:{line}'

    def _get_finding(self, finding, start_pos, end_pos):
        """ Convert finding text to [Message] """
        if finding:
            # Message(s)
            if isinstance(finding, list):
                return finding
            elif isinstance(finding, str):
                # String
                if start_pos and end_pos < start_pos:
                    self._end_pos = start_pos + len(finding)
                return [Message(finding, MessageSeverity.Warning)]
            else:
                raise GeneralException(f'{__name__}: Invalid finding type (must be str or list)')

    def extract_raw_finding(self) -> str:
        return ', '.join([m.message for m in self._finding]) if self._finding else EMPTY
