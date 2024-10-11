# ---------------------------------------------------------------------------------------------------------------------
# Enums.py
#
# Author      : Peter Heijligers
# Description : Enums
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from enum import Enum


class Color(object):
    RED = '\033[31m'
    GREEN = '\033[32m'
    ORANGE = '\033[33m'
    BLUE = '\033[36m'  # Was 34m
    PURPLE = '\033[35m'
    NC = '\033[0m'


# W10 does not seem to support ANSI cmd colors
class ColorWin(object):
    RED = ''
    GREEN = ''
    ORANGE = ''
    BLUE = ''
    PURPLE = ''
    NC = ''


class LogType(str, Enum):
    File = 'File'
    Stdout = 'Stdout'
    Both = 'Both'


class LogLevel(str, Enum):
    Error = 'Error'
    Info = 'Info'
    Warning = 'Warning'
    Verbose = 'Verbose'
    All = 'All'


class ResultCode(object):
    Ok = 'OK'
    Error = 'ER'
    Warning = 'WA'
    NotFound = 'NR'
    Equal = 'EQ'
    Cancel = 'CN'


class Language(object):
    General = 'General'
    iOS = 'iOS'
    Android = 'Android'
    Python = 'Python'
    Java = 'Java'
    CSharp = 'CSharp'
    VB = 'Visual Basic'
    NET = '.NET'
    JavaScript = 'JavaScript'
    TypeScript = 'TypeScript'
    PHP = 'PHP'
    HTML = 'HTML'

    ext2lang = {
        '.py': Python,
        '.java': Java,
        '.cs': CSharp,
        '.vb': NET,
        '.php': PHP,
        '.js': JavaScript,
        '.htm': HTML,
        '.html': HTML,
        '.ts': TypeScript,
    }


class SetMode(str, Enum):
    All = 'All'
    First = 'First'
    Where = 'Where'


class LeafType(str, Enum):
    Name = 'Name'
    Ext = 'Ext'


class CompareLevel(str, Enum):
    File = 'File'
    Dir = 'Dir'


class MessageSeverity(object):
    Info = 10
    Warning = 20
    Error = 30
    Completion = 40


class Output(str, Enum):
    File = 'File'
    Object = 'Object'


class ConfigType(str, Enum):
    String = 'String'
    Int = 'Int'
    List = 'List'
    Dir = 'Str'
    Bool = 'Bool'
    Float = 'Float'
    Path = 'Path'


class ApplicationTypeEnum(str, Enum):
    Any = 'Any'
    Standalone = 'Standalone'
    WebApp = 'Web application'
    Frontend = 'Frontend'
    Backend = 'Backend'
    Middleware = 'Middleware'
    API = 'API'


class ExecTypeEnum(str, Enum):
    Scan = 'Scan'
    DataFlow = 'DataFlow'
    Both = 'Both'
