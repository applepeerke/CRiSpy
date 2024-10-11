from src.core.Plugins.Const import CLASS
from src.gl.GeneralException import GeneralException
from src.gl.Parse.Parser_Base import *

FIRST_ELEMS_PY = {DEF: DEF, CLASS: CLASS, 'async': DEF}
FIND_TYPES = [DEF, CLASS, ALL]


class Parser_Python(Parser_Base):

    def __init__(self):
        super().__init__()

    def get_snippet(self,
                    find_type=ALL,
                    path=None,
                    find_name=None,
                    delimiters: list = None,
                    line_no_start: int = 0,
                    LC=False,
                    skip_comment=True,
                    unwrap=True,
                    method_name_if_class=None) -> list:
        """
        Get all lines of a MODULE, CLASS or a METHOD. Supports finding a method within a class.
        By default:
            Wrapped lines are expanded to a single line (un-wrapped).
            Comment is skipped.
            Snippet is returned in LC.
        Optionally from a specified line_no.
        """
        if not find_type or not path or find_type not in FIND_TYPES:
            raise GeneralException(f'{__name__}: Invalid input.')

        self._ns = path
        self._class_name = None
        self._line_no, self._line_no_start = 0, 0

        if not delimiters:  # default
            delimiters = ['(']

        lines = []
        str_pos, end_pos = 0, 0
        found = True if find_type == ALL else False
        self._comment_mode = None

        with open(path, 'rb') as fo:
            self.read_line(fo)

            # Line_no specified: Read until line is found
            while self._line != EOF and self._line_no < line_no_start and loop_increment(f'{__name__}.get_snippet-1'):
                self.read_line(fo)

            while self._line != EOF and loop_increment(f'{__name__}.get_snippet-2'):

                if self._is_valid_line(skip_comment):
                    stmt_type = self.get_next_elem()

                    # Stop - when source indentation is back to find_type (DEF, CLASS) level.
                    if found and self._s <= str_pos and find_type != ALL:
                        break

                    # Remember last class (before def is found)
                    if stmt_type == CLASS:
                        self._class_name = self.get_next_elem(delimiters=delimiters, LC=False)
                        # reset
                        self._ini_line()
                        stmt_type = self.get_next_elem()

                    # Start - when find_file type is found (e.g. 'def', 'class')
                    if not found and FIRST_ELEMS_PY.get(stmt_type) == find_type:
                        str_pos = self._s
                        next_elem = self.get_next_elem(delimiters=delimiters, LC=False)
                        if stmt_type == 'async':  # go to "def"
                            next_elem = self.get_next_elem(delimiters=delimiters, LC=False)
                        # Found - if (name specified and corresponds) or line_no_start was specified.
                        if (not find_name and line_no_start > 0) or next_elem == find_name:
                            # If both class AND method must be found, toggle from class to method mode.
                            if find_type == CLASS and method_name_if_class:
                                find_type = DEF
                                find_name = method_name_if_class
                            else:
                                self._line_no_start = self._line_no
                                found = True
                    if found or not find_name:
                        if LC:
                            self._line = self._line.lower()
                        lines.append([self._line, self._line_no])
                self.read_line(fo)

            return lines if not unwrap else un_wrap(lines)

    def _is_valid_line(self, skip_comment=True) -> bool:
        if not self._line:
            return False
        if not skip_comment:
            return True  # if comment is valid

        stripped = self._line.strip()
        if stripped.startswith('"""') and stripped.endswith('"""'):
            return False
        if stripped != '"""' and self._comment_mode == 'comments':
            return False
        elif stripped == '"""':  # Skip comment block
            self._comment_mode = 'comments' if not self._comment_mode else None
            return False
        elif stripped.startswith('#'):
            return False
        return True

    def get_sanitizer_name(self, line) -> str:
        return EMPTY
