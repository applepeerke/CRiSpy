from src.core.Plugins.Const import CLASS
from src.gl.GeneralException import GeneralException
from src.gl.Parse.Parser_Base import *

FIND_TYPES = [CLASS, ALL]


class Parser_Java(Parser_Base):

    def __init__(self):
        super().__init__()
        self._mode = None

    def get_snippet(self,
                    find_type=ALL,
                    path=None,
                    find_name=None,
                    delimiters: list = None,
                    line_no_start: int = 0,
                    LC=False,
                    skip_comment=True,
                    unwrap=True,
                    **kwargs) -> list:
        """
        Get all lines of a MODULE, or CLASS.
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
            delimiters = ['(', ';']

        lines = []
        str_pos, end_pos = 0, 0
        found = True if find_type == ALL else False
        self._mode = None

        with open(path, 'rb') as fo:
            self.read_line(fo)

            # Line_no specified: Read until line is found
            while self._line != EOF and self._line_no < line_no_start and loop_increment(f'{__name__}.get_snippet-1'):
                self.read_line(fo)

            while self._line != EOF and loop_increment(f'{__name__}.get_snippet-2'):

                if self._is_valid_line(skip_comment):
                    # Stop - when source indentation is back to find_type (CLASS) level.
                    if found and self._s <= str_pos and find_type != ALL:
                        break

                    # Remember last class
                    if self._line.startswith(CLASS):
                        self._class_name = self.get_next_elem(delimiters=delimiters, LC=False)
                        self._ini_line()
                    elif ' class ' in self._line:
                        self._class_name = self.find_and_set_pos(' class ')
                        self._class_name = self.get_next_elem(delimiters=delimiters, LC=False)
                        self._ini_line()

                    # Start - when class is found
                    if not found and find_type == CLASS:
                        str_pos = self._s
                        next_elem = self.get_next_elem(delimiters=delimiters, LC=False)
                        # Found - if (name specified and corresponds) or line_no_start was specified.
                        if (not find_name and line_no_start > 0) or next_elem == find_name:
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
        if stripped.startswith('/*') and stripped.endswith('*/'):
            return False
        elif stripped.startswith == '/*':  # Skip comment block
            self._mode = 'comments'
            return False
        elif stripped.endswith('*/'):
            self._mode = None
            return False

        return True
