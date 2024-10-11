import re

from src.gl.Const import EMPTY, BLANK, CSV_FIELD_LIMIT, APOSTROPHES, ALL
from src.gl.Functions import loop_increment, strip_crlf

EOF = 'b\'\''
CRLF = '\\r\\n'
DEF = 'def'
TAB = '\t'
BOL = 'BOL'


class Parser_Base(object):

    @property
    def EOL(self):
        return self._EOL

    @EOL.setter
    def EOL(self, value):
        self._EOL = value

    @property
    def delimiter(self):
        return self._delimiter

    @delimiter.setter
    def delimiter(self, value):
        self._delimiter = value

    @property
    def line(self):
        return self._line

    @line.setter
    def line(self, value):
        self._line = value

    @property
    def line_no(self):
        return self._line_no

    @line_no.setter
    def line_no(self, value):
        self._line_no = value

    @property
    def pos(self):
        return self._pos

    @property
    def ns(self):
        return self._ns

    @ns.setter
    def ns(self, value):
        self._line_no = 0
        self._ns = value

    @property
    def class_name(self):
        return self._class_name

    @property
    def line_no_start(self):
        return self._line_no_start

    @property
    def is_comment(self):
        return self._is_comment

    def __init__(self):
        self._pos = 0
        self._s = 0
        self._line = EMPTY
        self._line_no = 0
        self._delimiter = None
        self._BOL = False
        self._EOL = False
        self._ns = None
        self._class_name = None
        self._line_no_start = 0
        self._comment_mode = None
        self._is_comment = False
        self._comment_block = False

    def get_this_snippet(self, fo, skip_comment=True, unwrap=False, closing_chars=(']', ')', '}')) -> list:
        lines = []  # output

        # Get start indentation position
        self._ini_line()
        self.skip_blanks()
        if self._EOL:
            return []

        str_pos = self._pos
        while self._line != EOF and loop_increment(f'{__name__}.get_this_snippet'):
            if self._is_valid_line(skip_comment):
                lines.append([self._line, self._line_no])
            self.read_line(fo)
            self.skip_blanks()
            # Stop - when source indentation goes back.
            if self._pos <= str_pos:
                # Add closing character.
                if self._pos == str_pos and self.get_next_elem() in closing_chars:
                    lines.append([self._line, self._line_no])
                break
        if unwrap:
            lines = un_wrap(lines)
        return [line[0] for line in lines]

    def _is_valid_line(self, skip_comment=True) -> bool:
        raise NotImplementedError

    def get_snippet(self,
                    find_type=ALL,
                    path=None,
                    find_name=None,
                    delimiters: list = None,
                    line_no_start: int = 0,
                    LC=False,
                    skip_comment=True,
                    unwrap=True,
                    method_name_if_class=None):
        raise NotImplementedError

    def ini_file(self, ns):
        self.__init__()
        self._ns = ns

    def _ini_line(self):
        self._pos = 0
        self._s = 0
        self._EOL = False
        self._BOL = True

    def set_line(self, line):
        self._ini_line()
        self._line = line

    def read_line(self, fo):
        self._pos = 0
        self._EOL = False
        self._BOL = True
        self._line = self._read_line(fo)

        # EOF?
        if not self._line:
            self._line = EOF  # Even no byte representation
        if self._line == EOF:
            return

        # Remove byte representation ("b'mystring'") and crlf
        self._line = self._line[2:len(self._line) - 1]
        self._line = strip_crlf(self._line)

        # Empty line?
        if not self._line:
            self._EOL = True

        # Comment (mode?)
        self._set_comment(self._line)

    def _set_comment(self, line):
        w_line = line.lstrip()
        comment_line = False
        if w_line.startswith('#') \
                or w_line.startswith('//') \
                or (w_line.startswith('/*') and '*/' in w_line):
            comment_line = True
        elif '"""' in w_line:  # May be at beginning, but not always like in an assignment 'a = """'
            comment_line = self._check_comment_block(w_line, '"""')
        elif "'''" in w_line:
            comment_line = self._check_comment_block(w_line, "'''")
        elif w_line.startswith('/*'):
            self._comment_block = True
        elif w_line.startswith('*/'):
            self._comment_block = False
        self._is_comment = True if (comment_line or self._comment_block) else False

    def _check_comment_block(self, line, comment_block_string) -> bool:
        p = line.find(comment_block_string)
        if p == -1:
            return False
        p = line.find(comment_block_string, p + len(comment_block_string))
        if p > -1:  # 2 times a comment block string = single-line comment
            return True
        # Yes, comment block start/end! Toggle comment block.
        self._comment_block = True if not self._comment_block else False
        return True

    def _read_line(self, fo) -> str or None:
        line = str(fo.readline())
        if line:
            self._line_no += 1
        return line

    def find_and_set_pos(self, search_str, set_line=None, ini_pos=True, just_before=False, just_after=False,
                         ignore_case=False) -> bool:
        # Validate
        if not search_str:
            return False

        if set_line:
            self.set_line(set_line)
        else:
            self._EOL = False
            if ini_pos:
                self._pos = 0

        if ignore_case:
            x = re.search(search_str, self._line, re.IGNORECASE)
            self._pos = x.start() if x else -1
            match_str = x.group() if x else None
        else:
            self._pos = self._line.find(search_str, self._pos)
            match_str = search_str

        if self._pos == -1:
            self._EOL = True
            return False

        if just_before and self._pos > 0:
            self._pos -= 1
        elif just_after:
            for _ in range(0, len(match_str)):
                self.add_1_pos()  # Set EOL if needed
        self._BOL = False
        return True

    """
    E.g. get all super names in  "class myClass(mySuper1, common.mySuper2)"
    """

    def get_next_elems(self, delimiters: list = None, LC=True, ignore=None, last_part_only=False) -> list:
        elems = []
        elem = self.get_next_elem(delimiters=delimiters, LC=LC, ignore=ignore, last_part_only=last_part_only)
        while self._delimiter in delimiters and loop_increment(f'{__name__}.get_next_elems'):
            elems.append(elem)
            elem = self.get_next_elem(delimiters=delimiters, LC=LC, ignore=ignore, last_part_only=last_part_only)
            if not elem:
                break
        return elems

    def get_next_elem(self, delimiters: list = None, LC=True, ignore=None, last_part_only=False) -> str or None:
        """
        1. Skip leading blanks and '.' then
        2. Gets the element and
        3. Skips the delimiter
        """
        if ignore is None:  # Support empty list [] to find '.' too
            ignore = ['.']  # Default

        self.skip_blanks(ignore=ignore)
        self._s = self._pos
        self.skip_non_blanks(delimiters)

        next_elem = self._line[self._s:self._pos] if self._pos > self._s else None
        if not self.EOL:
            if next_elem and delimiters and self._line[self._pos] in delimiters:
                self.add_1_pos()
            elif delimiters and self._line[self._pos] not in delimiters:
                next_elem = None

        # Substitution: Optionally return last part only
        if next_elem and last_part_only:
            # Substitute with last part if it exists.
            p = next_elem.find('.') + 1  # Skip dot
            if 0 < p < len(next_elem):
                next_elem = next_elem[p:]

        return next_elem.lower() if (next_elem and LC) else next_elem

    def get_prv_elem(self, delimiters: list = None, skip_first: list = None, LC=True) -> str:
        """
        Gets the preceding element, keep position.
        """
        self.skipb_first(self.add_blank(skip_first))
        e = self._pos + 1
        self.skipb_non_blanks(delimiters)
        prv_elem = self._line[self._pos:e].strip() if e > self._pos else None
        # self.add_1_pos()  # keep position e
        return prv_elem.lower() if (prv_elem and LC) else prv_elem

    def skipb_first(self, skip_first):
        while not self._BOL and self._line[self._pos] in skip_first and loop_increment(f'{__name__}.skipb_first'):
            self.sub_1_pos()

    def skipb_blanks(self):
        while not self._BOL and self._line[self._pos] in [BLANK, TAB] and loop_increment(f'{__name__}.skipb_blanks'):
            self.sub_1_pos()

    def skip_blanks(self, ignore=None):
        ignore = self.add_blank(ignore)
        while not self._EOL and self._line[self._pos] in ignore and loop_increment(f'{__name__}.skip_blanks'):
            self.add_1_pos()

    def skip_non_blanks(self, delimiters: list = None):
        if self._pos >= 0:
            # First skip the delimiters to prevent looping, e.g. on " = " when pos on "=" and "=" in delimiters.
            if delimiters:
                while not self._EOL and self._line[self._pos] in delimiters \
                        and loop_increment(f'{__name__}.skip_non_blanks-1'):
                    self.add_1_pos()
            delimiters = self.add_blank(delimiters)
            while not self._EOL and self._line[self._pos] not in delimiters \
                    and loop_increment(f'{__name__}.skip_non_blanks-2'):
                self.add_1_pos()
            self._delimiter = None if self._pos == len(self._line) else self._line[self._pos]

    def skipb_non_blanks(self, delimiters: list = None):
        """ Skip back to 1st non-blank position"""
        if self._pos > 0:
            # First skip the delimiters to prevent looping, e.g. on " = " when pos on "=" and "=" in delimiters.
            if delimiters:
                while not self._BOL and self._line[self._pos] in delimiters \
                        and loop_increment(f'{__name__}.skipb_non_blanks-1'):
                    self.sub_1_pos()
            delimiters = self.add_blank(delimiters)
            self._BOL = False
            while not self._BOL and self._line[self._pos] not in delimiters \
                    and loop_increment(f'{__name__}.skipb_non_blanks-2'):
                self.sub_1_pos()

            if not self._BOL:
                self.add_1_pos()

    @staticmethod
    def add_blank(values) -> list:
        if not values:
            values = [BLANK, TAB]
        else:
            if BLANK not in values:
                values.extend(BLANK)
            if TAB not in values:
                values.extend(TAB)
        return values

    def add_1_pos(self):
        if self._pos < len(self._line):
            self._pos += 1
        if self._pos >= len(self._line):
            self._EOL = True

    def sub_1_pos(self):
        if self._pos > 0:
            self._pos -= 1
        if self._pos == 0:
            self._BOL = True

    @staticmethod
    def split_last_node(value, delimiters=None) -> (str, str):
        if not value:
            return EMPTY, EMPTY

        if not delimiters:
            delimiters = '.'
        p = len(value) - 1
        while p > 0 and value[p] not in delimiters and loop_increment(f'{__name__}.split_last_node'):
            p -= 1
        if p == 0:
            return EMPTY, value
        else:
            return value[:p], value[p + 1:len(value)]

    def get_struct(self, path, line, line_no_start, open_char='[', close_char=']') -> str:
        """
        Get all lines within e.g. a {} or [] structure
        """
        # E.g. resources=["*"] or resources=["*"],
        if line.endswith(close_char) or line.endswith(f'{close_char},'):
            return line

        self._line_no = 0
        result = EMPTY

        with open(path, 'rb') as fo:
            self.read_line(fo)

            # Line_no specified: Read until line is found
            while self._line != EOF and self._line_no < line_no_start \
                    and loop_increment(f'{__name__}.get_struct-1'):
                self.read_line(fo)

            if self._line.rstrip().endswith(open_char):  # Open-char found like "[", "{"
                result = self._line
                self.read_line(fo)
                while self._line != EOF and loop_increment(f'{__name__}.get_struct-2'):
                    result = f'{result}{self._line}'
                    if self._line.endswith(close_char) or self._line.endswith(f'{close_char},'):
                        break
                    self.read_line(fo)
        return result

    def get_assignment_target(self, line) -> str or None:
        self.set_line(line)
        name = self.get_next_elem(delimiters=['='])
        return name if name and self.get_next_elem() == '=' else None

    def get_assignment_source(self, line) -> str or None:
        self.set_line(line)
        name = self.get_next_elem(delimiters=['='])
        if name and self.get_next_elem() == '=':
            return self.get_next_elem(LC=False)

    def get_vars(self, search_str, line, delimiters, ignore) -> list:
        """
        Complex example:
            "logger.info(f'my text {password}')" /* Not comment, password should be found.
        """
        if not self.find_and_set_pos(search_str=search_str, set_line=line):
            return []
        # a. Skip the element with the found pattern
        self.get_next_elem(delimiters=delimiters, ignore=ignore)
        # b. Get all consecutive elements
        elms = self.get_next_elems(delimiters=delimiters, ignore=ignore)
        out_elms = []
        # c. Remove comment-elements
        apo_type = None
        comment_mode = False
        c_prv = EMPTY
        format_type = EMPTY

        # Only 1 element which has no apos: this is a var.
        if len(elms) == 1 and not any(a in elms[0] for a in APOSTROPHES):
            return elms

        for elm in elms:
            if '.format' in elm:
                comment_mode = False  # Python/Scala formatting may contain inline vars
                format_type = '.format'
            else:
                # Comment mode may be turned off in the middle, e.g. "text\\'.format("
                # comment_mode_set_off = False
                for c in elm:
                    if not apo_type:  # Start comment?
                        for a in APOSTROPHES:
                            if c == a:
                                apo_type = a  # Start-apo!
                                comment_mode = True
                                if c_prv in ('f', 's'):
                                    comment_mode = False  # Python/Scala formatting may contain inline vars
                                    format_type = c_prv
                    elif c == apo_type:  # End-apo and End comment
                        # comment_mode_set_off = True
                        apo_type = None
                        comment_mode = False
                    c_prv = c

            if not comment_mode and '.format' not in elm:
                out_elms.append(elm)

        # in a formatted string at least 1 element should be a variable
        var_token = '{' if format_type in ('f', '.format') \
                           or any('{}' in e for e in elms) \
                           or any('{}' in e for e in out_elms) \
            else '$' if format_type == 's' \
            else EMPTY
        if format_type == '.format':
            return out_elms
        return [] if \
            (not var_token and '+' not in elms) or \
            (var_token
             and not any(var_token in e for e in elms)
             and not any(var_token in e for e in out_elms)
             ) \
            else out_elms


def un_wrap(lines, open_char='(', close_char=')') -> list:
    unwrapped_lines = []
    unwrapped_line = EMPTY
    hooks, line_no_start, first_line_indentation = 0, 0, 0

    # Read snippet
    for line, line_no in lines:
        if not unwrapped_line:
            line_no_start = line_no

        # Get start of indent
        s, p = 0, 0
        while p < len(line) and line[p] == BLANK:
            s += 1
            p += 1

        if not unwrapped_line:
            first_line_indentation = s
            hooks = 0
        # Indent <= previous indent: Level break
        elif s <= first_line_indentation:
            hooks = 0

        # Count hooks
        while p < len(line):
            if line[p] == open_char:
                hooks += 1
            elif line[p] == close_char:
                hooks -= 1  # if ")" at indent level, hooks may become < 0
            p += 1

        # a. No open hooks (any more)
        if hooks <= 0:
            if unwrapped_line:
                unwrapped_line = f'{unwrapped_line} {line.strip()}'
                unwrapped_lines.append([unwrapped_line, line_no_start])
                unwrapped_line = EMPTY
            else:
                unwrapped_lines.append([line, line_no])  # Add original line

        # b. Open hooks
        else:
            # Expand line
            unwrapped_line = f'{unwrapped_line} {line.strip()}' if unwrapped_line else line.rstrip()
            # Check boundaries - line length
            if len(unwrapped_line) > CSV_FIELD_LIMIT:
                print('Parser_Base.unwrap: max. length reached, line is truncated.')
                unwrapped_lines.append([unwrapped_line, line_no_start])
                unwrapped_line = EMPTY

    # Last time
    if unwrapped_line:
        unwrapped_lines.append([unwrapped_line, line_no_start])

    return unwrapped_lines
