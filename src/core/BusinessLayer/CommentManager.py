# ---------------------------------------------------------------------------------------------------------------------
# CommentManager.py
#
# Author      : Peter Heijligers
# Description : Preserve the comment mode during scanning a source file.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-03-12 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.Const import CODE_LC, EMPTY

ML = 'MultiLineComment'
SL = 'SingleLineComment'

file_type_dict = {
    '.py': {ML: ('"""', '"""'), SL: ('# ', '""')},
    '.js': {ML: ('/*', '*/'), SL: ('* ', '//', '/*')},
    '.java': {ML: ('/*', '*/'), SL: ('* ', '//', '/*')},
    '.cs': {ML: ('/*', '*/'), SL: ('* ', '//', '/*')},
    '.rb': {ML: ('=begin', '=end'), SL: ('# ', '=begin')},
    '.aspx': {ML: ('<%--', '--%>'), SL: ('<%', '<!')},
    '.htm': {ML: ('<!--', '-->'), SL: ('<!',)},
    '.html': {ML: ('<!--', '-->'), SL: ('<!',)},
    '.test': {ML: ('"""', '"""'), SL: ('# ', '""')},
}

inline_comment = {
    '.py': '# ',
    '.java': '/*',
    '.rb': '# ',
}


class CommentManager(object):

    def __init__(self):
        self._file_type = EMPTY
        self._lin = EMPTY
        self._line_in_comment_block = False
        self._single_line_comment = False
        self._file_type_is_supported = True
        self._block_start = EMPTY
        self._block_end = EMPTY

    """ First step """

    def initialize_file(self, file_type: str):
        self._line_in_comment_block = False
        self._initialize_file_type(file_type)

    """  Second step """

    def is_comment(self, line: str) -> bool:
        # Unknown language, so comment unknown so assume it is no comment.
        if not self._file_type_is_supported:
            return False

        # Remove byte representation and CRLF and leading/trailing blanks
        self._lin = line[2:len(line) - 1]
        self._lin = self._lin[:-2] if self._lin.endswith('\\n') else self._lin
        self._lin = self._lin[:-2] if self._lin.endswith('\\r') else self._lin
        self._lin = self._lin.strip()

        # A. Multi-line comment
        # Line = start delimiter: Toggle block start/end
        if self._lin == self._block_start:
            self._line_in_comment_block = True if not self._line_in_comment_block else False
            # Block start = Line starts & does not end with comment delimiter
        elif self._lin[:len(self._block_start)] == self._block_start and not self._lin.endswith(self._block_end):
            self._line_in_comment_block = True
            # Block end = Line ends with end delimiter
        elif self._lin.endswith(self._block_end):
            self._line_in_comment_block = False
            return True  # Block has ended but this line is still a comment

            # Special cases
        if self._file_type == '.rb' and self._lin == '__END__':  # EOF
            self._line_in_comment_block = True

        if self._line_in_comment_block:
            return True

        # B. Single line comment (may occur even in unsupported file types)
        # validate
        if len(self._lin) < 3:
            return False

        self._set_single_line_comment(self._lin[:2])
        if self._single_line_comment:
            return True
        return False

    """  Third step (after pattern is found) """

    def is_inline_comment(self, line: str, index: int) -> bool:
        if index <= 0:
            return False

        # A. File type specific comment syntax
        # Consider as comment when found position is after start of inline comment.
        if self._file_type in inline_comment \
                and inline_comment[self._file_type] in line \
                and line.find(inline_comment[self._file_type]) < index:
            return True

        # B. General comment syntax (apostrophes)
        # Consider as "comment" when found position is part of a constant (e.g. "myEncryptionCipher").
        p = index
        while p < len(line) and line[p].lower() in CODE_LC:
            p += 1
        if p < len(line) and line[p] in ['\'', '"']:
            apo = line[p]
            p = index
            while p > 0 and line[p].lower() in CODE_LC:
                p -= 1
            if line[p] == apo:
                return True
        return False

    def _initialize_file_type(self, file_type):
        if file_type == self._file_type.lower():
            return

        self._file_type = file_type.lower()

        self._file_type_is_supported = self._file_type in file_type_dict

        if self._file_type_is_supported:
            self._block_start = file_type_dict[self._file_type][ML][0]
            self._block_end = file_type_dict[self._file_type][ML][1]

    def _set_single_line_comment(self, line_start):
        # This is  a comment also in non-supported file types
        if line_start in ['/*', '//']:
            self._single_line_comment = True
            return

        if not self._file_type_is_supported:
            self._single_line_comment = False
            return

        self._single_line_comment = line_start in file_type_dict[self._file_type][SL]

        if self._file_type in ['.htm', '.html'] \
                and self._single_line_comment \
                and 'script' in self._lin.lower():
            self._single_line_comment = False
