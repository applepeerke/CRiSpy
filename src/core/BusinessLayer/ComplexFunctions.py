# ---------------------------------------------------------------------------------------------------------------------
# ComplexFunctions.py
#
# Author      : Peter Heijligers
# Description : Like regex, find_file index in a source line
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-08-16 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import codecs
import re

from src.core.BusinessLayer.ExpressionManager import ExpressionManager
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.BusinessLayer.PrivacyManager import PrivacyManager
from src.core.DataLayer import FindingTemplate as template
from src.core.DataLayer.Finding import Finding
from src.core.DataLayer.SecurityHeaders import Singleton as securityHeaders
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import LC, UC, NUM, SPECIAL_ALLOWED_CHARS, EMPTY
from src.gl.Functions import get_word_rate, loop_increment
from src.gl.Parse.Parser_Python import Parser_Python, BLANK, APOSTROPHES
from src.gl.Validate import isInt

PGM = 'ComplexFunctions'
CF_ = '*CF_'
CF_HARDCODED_KEY = '*CF_HARDCODED_KEY'
CF_REDOS = '*CF_REDOS'
CF_LOG = '*CF_LOG'
CF_LOGGER = '*CF_LOGGER'
CF_TRACE = '*CF_TRACE'
CF_PRINT = '*CF_PRINT'
CF_PARM_CHECK = '*CF_PARM_CHECK'
CF_WHERE = '*CF_WHERE'
CF_HEADER = '*CF_HEADER'
CF_SCRIPT = '*CF_SCRIPT'
CF_RESOURCES = '*CF_RESOURCES'
CF_ACTIONS = '*CF_ACTIONS'
CF_PRINCIPALS = '*CF_PRINCIPALS'
CF_EMAIL = '*CF_EMAIL'
CF_PHONE = '*CF_PHONE'
CF_VERIFY = '*CF_VERIFY'
CF_AUTOESCAPE = '*CF_AUTOESCAPE'
CF_INPUT = '*CF_INPUT'

CF_PARM_MIN_TOKEN_LENGTH = 'minimum_token_length'

html_script_functions = ('href', 'src', 'onload')

# Hardcoded key definitions
_alphaLower = 'AlphaLower'
_alphaUpper = 'AlphaUpper'
_num = 'num'
_allowed = 'otherNormal'
_other = 'other'
_complex = 'allPresent'
charTypes = {
    _alphaLower: False,
    _alphaUpper: False,
    _num: False,
    _allowed: False,
    _other: False,
    _complex: False
}

first_reDoS = True

parser = Parser_Python()
privacy_manager = PrivacyManager()
expression_manager = ExpressionManager()
inline_comment_delimiters = [BLANK, '(', ')']
REGEX_ALLOWED_SQL_WHERE = re.compile(r"^[a-z .=<>!*?)'\"\\/\d-]$")  # alphanum, blank, operators, apostrophs
REGEX_EMAIL = re.compile(r'[\S@\w]')
REGEX_NO_VAR = re.compile(r"^[()@:%_\\+.~#?&/= \w\d-]*$")
REGEX_PHONE_NUMBER = re.compile(r'^[+() \d]*$')
"""
Hardcoded key functions
"""

FM = Findings_Manager()
Headers = securityHeaders()


def _is_where_sanitized(line, strpos) -> bool:
    # State is vulnerable. Sane if als vars are sanitized
    # E.g. "db_value=${mysql.escape(input_value)}" is sane.
    i = strpos
    var_count, sane_count = 0, 0
    while True and loop_increment(f'{__name__}'):
        s = line.find('{', i)
        if s == -1:
            break
        e = line.find('}', s)
        if e == -1:
            break
        # Now var is found (possible user input)
        var_count += 1
        if 'escape(' in line[s + 1:e]:
            sane_count += 1
        i = e  # next
    return var_count > 0 and var_count == sane_count


class ComplexFunctions(object):

    @property
    def output_dir(self):
        return self._output_dir

    @output_dir.setter
    def output_dir(self, value):
        self._output_dir = value

    def __init__(self):
        self._output_dir = None
        self._headers = {}

    def get_index(self, line: str, pattern: str, file_name: str, file_ext: str, line_no: int = 0, path=None) -> int:
        """
        Pattern has the form "*CF_name(parm1, parm2, ...)"
        """
        result = -1
        file_name = f'{file_name}{file_ext}'

        # validation
        if line == EMPTY or not pattern.startswith(CF_):
            return result

        # Get optional parameters
        pattern_name, parms = self._get_parms(pattern)

        # a. Hardcoded key
        if pattern_name == CF_HARDCODED_KEY:
            # minimum token length
            dft = 30
            min_token_length = dft if not parms else int(parms[0]) if isInt(parms[0]) else dft
            # Return HK-index or -1
            result = self._get_index_of_hardcoded_key(line, min_token_length)

        # b. Regex Denial of Service
        elif pattern_name == CF_REDOS:
            result = self._get_reDoS_index(line, file_name, line_no)

        elif pattern_name in (CF_LOG, CF_LOGGER, CF_TRACE, CF_PRINT):
            # Skip if comment only. In case of Log/Logger/Print, also skip if not privacy sensitive.
            result = self._get_index_of_sensitive_info(line.lower(), pattern_name[4:].lower())

        # c. Check parameters
        elif pattern_name == CF_PARM_CHECK:
            result = self._check_parameters_of(parms[0], path, line, line_no) if parms and parms[0] else -1

        # d. WHERE
        elif pattern_name == CF_WHERE:
            result = self._where(line.lower())

        # e. Header
        elif pattern_name == CF_HEADER:
            self._security_header(line)
            result = self._get_assigner(line, must_be_string=True)

        # f. Resources
        elif pattern_name in (CF_RESOURCES, CF_ACTIONS, CF_PRINCIPALS):
            pattern = pattern_name[4:].lower()
            result = self._AWS_config_wildcards(pattern, path, line, line_no)

        # e. Email
        elif pattern_name == CF_EMAIL:
            result = self._email(line)

        # e. Phone number
        elif pattern_name == CF_PHONE:
            result = self._phone_number(pattern=pattern_name[4:].lower(), line=line)

        # f. Verify
        elif pattern_name == CF_VERIFY:
            result = self._verify(pattern=pattern_name[4:].lower(), expression=parms, line=line)

        # g. AutoEscape
        elif pattern_name == CF_AUTOESCAPE:
            result = self._autoescape(pattern=pattern_name[4:].lower(), expression=parms, line=line)

        # h. Href
        elif pattern_name == CF_SCRIPT:
            result = self._has_variable(line, pattern_name=parms[0], parms=parms)

        # i. Href
        elif pattern_name == CF_INPUT:
            result = self._has_variable_value(line, parms)
        return result

    @staticmethod
    def _get_parms(pattern) -> (str, list):
        """
        pattern(expr)
        Example: verify(contains ssl and false)
        """
        parm_list = []
        parm_pos = pattern.find("(")

        if parm_pos == -1:
            return pattern, parm_list  # No parameters

        between_parentheses = pattern[parm_pos + 1:pattern.find(")")].split(',')
        if between_parentheses:
            if ',' in between_parentheses:
                parm_list = between_parentheses.split(',')
            elif ' ' in between_parentheses:
                parm_list = between_parentheses.split()
            else:
                parm_list = between_parentheses
            if parm_list is None or len(parm_list) == 0:
                parm_list = []
        parm_list = [p.strip() for p in parm_list]
        return pattern[:parm_pos], parm_list

    def _get_index_of_hardcoded_key(self, line: str, minimum_number_of_tokens: int) -> int:
        """
        Get the index of the key of the hardcoded key assignment, or -1.
        """
        line_len = len(line)
        i = 0
        start_delimiter = BLANK
        found = False

        # Until EOL:
        while i < line_len:
            if i == line_len:
                break

            i = self._get_assigner(line, i, must_be_string=False)
            if i == -1:
                break

            # Hardcoded key may start with a delimiter (apostrophe).
            if line[i] in ['"', '\'']:
                start_delimiter = line[i]
                i += 1

            # Start
            for k, v in charTypes.items():
                charTypes[k] = False

            e = i
            # Read until delimiter (apostrophe, blank or path token [\, .])
            while e < line_len and line[e] not in [' ', '.', ',', ';', start_delimiter]:
                if not charTypes[_complex]:
                    self._set_char_types(charTypes, line[e])
                e += 1
            token_length = e - i
            # valid?
            if e >= line_len or not line[e] in ['.', ',', ';']:  # not a filename or column delimiter
                token = line[i:e]
                if token_length > minimum_number_of_tokens \
                        or (token_length > 20
                            and charTypes[_complex] is True
                            and not (token.startswith('r') and token[1] in ('\'', '"'))):  # not regex
                    # Not more than 50% of the token characters may consist of words
                    if get_word_rate(token) < 50:
                        found = True
                        break
                i = e

        # Aftercare
        if found:
            stripped_line = line.strip()
            if stripped_line.startswith('<') and stripped_line.endswith('>'):
                return -1
            return i
        return -1

    @staticmethod
    def _get_assigner(line, i=0, must_be_string=False) -> int:
        # Till EOL or found
        while i < len(line):
            # Go to start of key after an assignment ('=' or ':')
            while i < len(line) and line[i] not in ['=', ':']:
                i += 1
            # Skip oper and blanks
            while i < len(line) and line[i] in ['=', ':', ' ']:
                i += 1

            # Evaluate
            if i < len(line) and (not must_be_string or line[i] in APOSTROPHES):
                return i  # Found
            i += 1
        return -1

    @staticmethod
    def _check_hardcoded_string(line, strpos=0, regex=None, match_is_finding=True) -> int:
        """
        Get 1st text between apostrophes starting at strpos.
        If no apo's, it's ok, this may be a function.
        :return: Pos of hardcoded string
        """
        # Till EOL or found
        s = strpos

        # Skip blanks.
        while s < len(line) and line[s] == BLANK:
            s += 1
        # Find 1st apostroph.
        if strpos == 0:
            while s < len(line) and line[s] not in APOSTROPHES:
                s += 1
        if s == len(line) or line[s] not in APOSTROPHES:
            return -1
        apo = line[s]
        s += 1  # after apo
        e = s

        while e < len(line) and line[e] != apo:
            e += 1
        if e == len(line):
            return -1

        # Finding if there is a match or no match
        if not line[s:e] \
                or (regex.match(line[s:e]) and match_is_finding is False) \
                or (not regex.match(line[s:e]) and match_is_finding is True):
            return -1  # No finding
        return s

    @staticmethod
    def _set_char_types(char_types: dict, value: str):
        """
        Which char types are present in the string [A-Z, a-z, 0-9, Special_chars, Other]?
        """
        # Do not count the (closing) apostrophe as a special character
        if value in ['"', '\'']:
            return
        changed = False
        if not char_types[_alphaLower] and \
                value in LC:
            char_types[_alphaLower] = True
            changed = True
        elif not char_types[_alphaUpper] and \
                value in UC:
            char_types[_alphaUpper] = True
            changed = True
        elif not char_types[_num] and \
                value in NUM:
            char_types[_num] = True
            changed = True
        elif not char_types[_allowed] and \
                value in SPECIAL_ALLOWED_CHARS:  # Not "-", this is used in GUIDs:
            char_types[_allowed] = True
            changed = True
        elif not char_types[_other]:
            if value not in LC and \
                    value not in UC and \
                    value not in NUM and \
                    value not in SPECIAL_ALLOWED_CHARS:
                char_types[_other] = True
                changed = True
        # Determine "Complex" state (N.B. Ignore "_alphaNormal")
        if changed and \
                char_types[_alphaLower] and \
                char_types[_alphaUpper] and \
                char_types[_num] and \
                char_types[_other]:
            char_types[_complex] = True
        return False

    def _get_reDoS_index(self, line, file_name, line_no: int) -> int:
        """
        Group expressions with repetition or alternation, that is repeated, is vulnerable.
        E.g: (\d+)+, (\d|\s)+, where "+" may be "*"
        """
        result = -1
        reDoS_indexes = []

        # Find "closing repetition".
        if line.find(')*') == -1 and line.find(')+') == -1:
            return -1

        # Now assume it is regex. Get all occurrences of closing repetitions.
        closing_repetitions = []
        i = 0
        e = len(line)
        while i < e:
            if i < e - 1 and line[i] == ')' and line[i + 1] in ['*', '+']:
                closing_repetitions.append(i)
            i += 1

        # From every occurrence,
        # go backwards in the line to opening hook "(". Skip inner hooks "(...)".
        for p in closing_repetitions:
            redos_start = -1
            redos_end = p + 1
            redos_flag = False
            pipe_flag = False
            hooks = 0
            p -= 1  # Skip 1st ")"
            # Meanwhile, if [")*", ")+", |] is present, the regex is vulnerable.
            while p >= 0:
                if line[p] == ')':
                    hooks += 1
                elif line[p] == '(':
                    if pipe_flag:
                        # Possible reDoS found!!!
                        redos_flag = True
                    if hooks == 0:
                        break
                    hooks -= 1
                # Things like ')+', ']+', '\d+', '\s+'
                elif line[p] in ['*', '+'] and p > 0 and line[p - 1] in [')', ']', 'd', 's']:
                    # Ignore concatenations like ')+(' and ')+"'
                    if line[p + 1] not in ['"', '(']:
                        # Possible reDoS found!!!
                        redos_flag = True
                elif line[p] == '|' and p > 0 and line[p - 1] != '|' and line[p + 1] != '|':
                    pipe_flag = True
                p -= 1

            # if reDoS found, substitute index of closing hook with that of starting hook.
            if redos_flag:
                redos_start = p
            reDoS_indexes.append([redos_start, redos_end])

        if reDoS_indexes:
            reDoS_findings = []
            for i in reDoS_indexes:
                if i[0] != -1:
                    finding = codecs.decode(line[i[0]:i[1] + 1], 'unicode_escape')
                    reDoS_findings.append(
                        Finding(file_name, line_no, start_pos=i[0], end_pos=i[1], finding=finding))
                # For the time being, return the 1st reDoS found (per file)
                if result == -1:
                    result = i[0] if i[0] > -1 else 0
            self._write_reDos(reDoS_findings)
        return result

    @staticmethod
    def _write_reDos(reDoS_findings):
        FM.initialize(template.REDOS)
        FM.write_results(reDoS_findings, template.REDOS, f'{Session().log_dir}reDoS.txt')

    @staticmethod
    def _get_variables(search_string, line) -> list:
        """
        Get variable names in ... from a function name like logger.error(...) or trace(...).
        """
        return parser.get_vars(
            search_string, line, delimiters=inline_comment_delimiters, ignore=inline_comment_delimiters)

    def _get_index_of_sensitive_info(self, line, pattern_name) -> int:
        """
        :return pattern position if possible privacy violation is found, or -1 if not found.
        Ignore occurrences in comment.
        """
        # Validation
        not_found = -1
        pattern_type = 'LOG' if pattern_name in ('log', 'logger') \
            else 'TRACE' if pattern_name == 'trace' \
            else 'PRINT'
        # Find
        p = line.find(pattern_name)
        if p == -1:
            if pattern_type == 'TRACE':  # Also try "tracing"
                pattern_name = 'tracing'
                p = line.find(pattern_name)
            if p == -1:
                return not_found

        p_pattern = p

        if pattern_type == 'LOG':
            e = p + len(pattern_name)
            if e >= len(line) or line[e] not in ('.', '('):
                return not_found  # do not find "logic" or "AuditLog\n" but "log.ic".
            if line.find(f'.get{pattern_name}') > -1:
                return not_found  # getLog/getLogger is a definition, no sensitive info.
            if line.find('.getmessage()') > -1:
                return not_found  # .getMessage() gets exception description, is safe.
            if len(line) < p + 12 or line[p:p + 12] == f'{pattern_name}.debug':
                return not_found  # debug logging is acceptable to contain sensitive info.
            if pattern_name == 'logger' and line.find('exc_info=True') > -1:
                return p_pattern
        elif pattern_type == 'TRACE':
            if 'track' in line:  # sanitizer
                return not_found
            if line.find('stacktrace') > -1:  # E.g. "exception.printStackTrace()"
                return p_pattern
        elif pattern_type == 'PRINT':
            if p_pattern > 0 and line[p - 1] != BLANK:  # leading blank and hook
                return not_found

        # Get variables.
        variables = self._get_variables(pattern_name, line)

        for var in variables:
            if pattern_type == 'TRACE':  # Examine all trace variables
                return p_pattern
            # LOG/PRINT: 1 var without apos or formatted string with privacy sensitive vars
            elif (len(variables) == 1 and not any(a in variables[0] for a in APOSTROPHES)) \
                    or ComplexFunctions._is_privacy_sensitive_var(var):
                return p_pattern
        return not_found

    @staticmethod
    def _check_parameters_of(method_name, path, line, line_no) -> int:
        """
        :return -1 if nothing to report, >0 if too few getattr parameters
        """
        if method_name != 'getattr':
            return -1  # Nothing to report

        if line.rstrip().endswith('('):
            line = parser.get_struct(path, line, line_no_start=line_no, open_char='(', close_char=')')

        i = line.find('getattr(')
        i_save = i
        if i > 0:
            # Default specified?
            i = line.find('default=', i)
            if i > 0:
                return -1  # Nothing to report
            # Else 3 parameters specified?
            i = line.find(',', i + 1)
            if i > 0:
                i = line.find(',', i + 1)
                if i > 0:
                    # 3rd parameter specified
                    return -1  # Nothing to report
        return i_save

    @staticmethod
    def _where(line) -> int:
        i = line.find('where ')
        if i == -1:
            return -1
        # From WHERE on, only alphanum, space, =, operators, quotes and closing hook are ok.
        if all(REGEX_ALLOWED_SQL_WHERE.match(x) for x in line[i:]):
            return -1
        # Check if all vars are sanitized
        return -1 if _is_where_sanitized(line, i) else i

    @staticmethod
    def _is_privacy_sensitive_var(var) -> bool:
        privacy_manager.set_patterns()
        if not var or not privacy_manager.patterns:
            return False

        # Remove non-alphabetic chars
        var = re.sub('[^A-Za-z0-9]+', '', var)

        # An ID is ok.
        if var.startswith('id') or var.endswith('id'):
            return False

        # Sensitive if var exists in any of the privacy patterns.
        if any(p in var for p in privacy_manager.patterns):
            return True

    @staticmethod
    def _security_header(line):
        """
        Keeps security headers in a coulant way.
        """
        if 'header' not in line.lower():
            return

        Headers.set_header_from_line(line, 'Code base')

    @staticmethod
    def _email(line) -> int:
        if not REGEX_EMAIL.match(line):
            return -1
        # Last character before "@" must be alphanum.
        p = line.find('@')
        return p if p > -1 and line[p - 1].isalnum() else -1

    def _phone_number(self, pattern, line) -> int:
        return -1 if line.find(pattern) == -1 else \
            self._check_hardcoded_string(line, regex=REGEX_PHONE_NUMBER, match_is_finding=True)

    @staticmethod
    def _verify(pattern, expression, line) -> int:
        """
        Example: pattern "*CF_VERIFY(contains, or, false, none)":
        meaning expression contains "false" or "none".
        Search for strings in expressions like "Verify_ssl=False", "VERIFYSSL = False"
        """
        return expression_manager.evaluate(pattern, expression, line)

    @staticmethod
    def _autoescape(pattern, expression, line) -> int:
        """
        Example: pattern "*CF_AUTOESCAPE(contains, or, false, none)":
        meaning expression contains "false" or "none".
        Search for strings in expressions like "autoescape=False", "autoescape = False"
        """
        return expression_manager.evaluate(pattern, expression, line)

    def _has_variable(self, line, pattern_name, parms=None) -> int:
        """
        href=, src=, onload=
        """
        find_str = pattern_name
        if parms and parms[0].lower() in html_script_functions:  # href=, src=, onload=
            find_str = f'{pattern_name}='

        p = line.find(find_str)
        return -1 if p == -1 else \
            self._check_hardcoded_string(line, strpos=p + len(find_str), regex=REGEX_NO_VAR, match_is_finding=False)

    def _has_variable_value(self, line, parms) -> int:
        """
        Sane:       <input type="submit" value="Primary Submit" class="button is-primary" />
        Vulnerable: <input type="submit" value="${param.xss}" class="button is-primary" />
        """
        find_str = 'value='
        if not parms or len(parms) < 1 or line.find(parms[0]) == -1 or line.find(find_str) == -1:
            return -1

        p = line.find(find_str)
        return -1 if p == -1 else \
            self._check_hardcoded_string(line, strpos=p + len(find_str), regex=REGEX_NO_VAR, match_is_finding=False)

    @staticmethod
    def _AWS_config_wildcards(pattern, path, line, line_no) -> int:
        """
        Get unwrapped line containing resources["*", "myItem/*", ...]
        return: 0 (found) if any item ends with "*", else -1 (not found).
        """
        p = line.find(pattern)
        if p == -1 or line.find('[', p) == -1:
            return -1

        # a. Get unwrapped line containing resources["*", "myItem/*", ...]
        line = parser.get_struct(path, line, line_no_start=line_no, open_char='[', close_char=']')
        # Remove trailing "blanks ]," split list elements and check if any item ends with a wildcard.
        if any(len(i) > 2 and i[-2] == '*' for i in line.rstrip(',]').rstrip().split(',')):
            return p

        if pattern == 'principals' and 'AnyPrincipal' in line:
            return p

        # b. Single-line-list, e.g. "    actions=["*"], resources=["*"], effect=aws_iam.Effect.ALLOW"
        e = line.find(']', p)
        if e > 1 and line[e - 2] == '*':
            return p
        return -1
