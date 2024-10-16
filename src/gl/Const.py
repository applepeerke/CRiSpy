SRC = 'src'
TESTS = 'tests'
APP_NAME = 'CRiSp'
MODULE_CORE = 'core'
MODULE_DB = 'db'

RED = 'RED'
GREEN = 'GREEN'
BLUE = 'BLUE'

CURRENT = 'CURRENT'
QUIT = 'QUIT'

ALL = 'All'
ANY = 'Any'
NONE = 'None'
ASTERISK = '*'
CALCULATE = 'Calculate'

BASE_OUTPUT_SUBDIR = 'crisp_result'
EMPTY = ''
BLANK = ' '
N = 'n'
Y = 'y'
UNKNOWN = 'Unknown'
NOT_FOUND = 'Not found'
FALSE = 'False'
TRUE = 'True'
DONE = 'Done.'
OK = 'OK'
ER = 'ER'

LC = 'abcdefghijklmnopqrstuvwxyz'
UC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
NUM = '0123456789'
SPECIAL_ALLOWED_CHARS = '_'
WORD_CHARS = f'{LC}{UC}'
CODE_LC = f'{LC}{NUM}{SPECIAL_ALLOWED_CHARS}'

MAX_READS_PER_FILE = 100000
MAX_WRITES_PER_FILE = 100000
MAX_VALIDATION_ERRORS = 100
MAX_LOOP_COUNT = 10000
MAX_PATTERN_LENGTH_AT_QUICK_SCAN = 50
MAX_CONFIG_FILE_SIZE_IN_BYTES = 1000000
CSV_FIELD_LIMIT = 131000
XLS_FIELD_LIMIT = 32000
APP_FIELD_LIMIT = 1000
RESULTS_DIR = 'Results'
SEARCH_DATA_PATH = 'SEARCH_DATA_PATH'
CATEGORY_GENERAL = 'General'
CATEGORY_LANGUAGE = 'Language'
CATEGORY_COMPANY = 'Company'
PROJECT = 'Project'
PROGRAM_LANGUAGE = 'ProgramLanguage'
FINDINGS_INTERNAL = 'Findings_Internal'
FINDINGS = 'Findings'
CSV_EXT = '.csv'
CSV_FINDINGS = 'Findings.csv'
CSV_SEARCH_PATTERNS = 'SearchPatterns.csv'
MODEL_FINDINGS = 'Findings'
MODEL_SEARCH_PATTERNS = 'SearchPatterns'
TXT_EXT = '.txt'
CVE_CLI = 'CVE_CLI'

SEARCH_ONLY_FOR_ASSIGNED_TO = 'AssignedTo'

APOSTROPHES = ('\'', '"', "\\'")
DB_LIST_REPRESENTATION_SUBSTITUTE = ('\'', '"', "\\'", ',')

PYTHON_BUILT_INS = [
    "abs", "aiter", "all", "any", "anext", "ascii", "bin", "bool", "breakpoint", "bytearray", "bytes",
    "callable", "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir", "divmod", "enumerate",
    "eval", "exec", "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash",
    "help", "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len", "list", "locals",
    "map", "max", "memoryview", "min", "next", "object", "oct", "open", "ord", "pow", "print", "property",
    "range", "repr", "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod", "str",
    "sum", "super", "tuple", "type", "vars", "zip"]

SPECIAL_CHARS = '!@#$%&*()-,.;: ''"|\\?/[]'
