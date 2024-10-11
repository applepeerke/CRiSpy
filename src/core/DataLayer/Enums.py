from enum import Enum

from src.gl.Const import EMPTY


class FrameworkName(object):
    Unknown = 'Unknown'
    Rest = 'RestFramework'
    Django = 'Django'
    SQLAlchemy = 'SQLAlchemy'
    Marshmallow = 'Marshmallow'
    Flask = 'Flask'
    FastApi = 'FastApi'
    Pydantic = 'Pydantic'
    K8s = 'K8s'
    AWS = 'AWS'
    JS = 'JS'
    Spring = 'Spring'
    NET = '.NET'


class SecurityTopic(object):
    Security = 'Security'
    Authentication = 'Authentication'
    Authorization = 'Authorization'
    Configuration = 'Configuration'
    Endpoint_analysis = 'Endpoint_analysis'
    Validation = 'Validation'
    Session = 'Session'


class SecurityPattern(object):
    Vulnerable_endpoint = 'vulnerable_endpoints'  # Important name, Extra generated findings.csv
    Security_headers = 'security_headers'
    Request = 'request'
    Header = 'header'
    Authentication = 'authentication'
    Session = 'session'
    Cookie = 'cookie'
    Token = 'token'
    CSRF = 'CSRF protection'
    Authorisation = 'authorisation'
    Validation = 'validation/sanitizing'
    ErrorHandling = 'error handling'
    Logger = 'logging'
    Config = 'configuration'
    Encoding = 'output encoding'


class ColorText(object):
    Green = 'GREEN'
    Red = 'RED'
    Orange = 'ORANGE'
    Nc = 'NC'
    Blue = 'BLUE'


class Purpose(object):
    Empty = ''
    Locate = 'Locate'
    New = 'New'
    Expected = 'Expected'
    Additional = 'Additional'

    values = (Empty, Locate, New, Expected, Additional)
    search_pattern_values = (Empty, Locate)


class Severity(object):
    Informational = 'Informational'
    Low = 'Low'
    Medium = 'Medium'
    High = 'High'


class OWASP2017(object):
    A1 = 'A1-Injection'
    A2 = 'A2-Broken Authentication'
    A3 = 'A3-Sensitive Data Exposure'
    A4 = 'A4-XML External Entities'
    A5 = 'A5-Broken Access Control'
    A6 = 'A6-Security Misconfiguration'
    A7 = 'A7-Cross Site Scripting (XSS)'
    A8 = 'A8-Insecure Deserialization'
    A9 = 'A9-Using Components With Known Vulnerabilities'


class OWASP2021(object):
    A01 = 'A01-Broken Access Control'
    A02 = 'A02-Cryptographic Failures'
    A03 = 'A03-Injection'
    A04 = 'A04-Insecure Design '
    A05 = 'A05-Security Misconfiguration'
    A06 = 'A06-Vulnerable and Outdated Components'
    A07 = 'A07-Identification and Authentication Failures'
    A08 = 'A08-Software and Data Integrity Failures'
    A09 = 'A09-Security Logging and Monitoring Failures '
    A10 = 'A10-Server-Side Request Forgery'


class NotInternetFacing(object):
    Any = EMPTY
    Exclude = 'Exclude'
    Include = 'Include'


class ContextType(object):
    Config = 'Config'
    Model = 'Model'
    Serializer = 'Serializer'


class ConfigFileType(object):
    Json = 'json'
    Yaml = 'yaml'

    values = (Json, Yaml)


class ClassSourceUsage(object):
    Def = 'Definition'
    Import = 'Import'


class SanitizerType(object):
    Enum = 'Enum'
    Serializer = 'Serializer'
    Entity = 'Entity'
    Validator = 'Validator'


"""
DBAction Enums for OpenAPI docs
"""
# DB actions
ETL_IMPORT = 'Import status CSV'
DB_REBUILD = 'Rebuild a company or project'
DB_IMPORT_COMMENTED_FINDINGS = 'Import MarkedFindings.csv'
DB_IMPORT_PROJECT_EXTRA = 'Import ProjectExtra.csv'
DB_CLEANUP = 'Clean up data'
DB_DELETE = 'Delete a Project'
DB_RENAME = 'Rename a Project'
DB_MIGRATE = 'Migrate a table'
DB_CHECK_CONSISTENCY = 'Check if the database is consistent'
ACTION_SYNCHRONIZE_CVE_FROM_NIST = 'Synchronize CVE from NIST'
ACTION_CLEANUP_REBUILD_HISTORY = 'Clean up the csv rebuild history'


class DBAction(str, Enum):
    ImportFindings = ETL_IMPORT
    Rebuild = DB_REBUILD
    ImportCommentedFindings = DB_IMPORT_COMMENTED_FINDINGS
    ImportProjectsExtra = DB_IMPORT_PROJECT_EXTRA
    CleanUp = DB_CLEANUP
    Delete = DB_DELETE
    Rename = DB_RENAME
    Migrate = DB_MIGRATE
    CheckConsistency = DB_CHECK_CONSISTENCY
    SynchronizeCVE = ACTION_SYNCHRONIZE_CVE_FROM_NIST
    CleanUpRebuildHistory = ACTION_CLEANUP_REBUILD_HISTORY


class DBActionProject(str, Enum):
    Rebuild = DB_REBUILD
    Delete = DB_DELETE
    Rename = DB_RENAME
    CleanUpRebuildHistory = ACTION_CLEANUP_REBUILD_HISTORY


class DBActionTable(str, Enum):
    Migrate = DB_MIGRATE


class DBActionGeneral(str, Enum):
    CheckConsistency = DB_CHECK_CONSISTENCY
    CleanUp = DB_CLEANUP
    ImportCommentedFindings = DB_IMPORT_COMMENTED_FINDINGS
    ImportProjectsExtra = DB_IMPORT_PROJECT_EXTRA


class ETLAction(str, Enum):
    Load = 'load'
    Merge = 'merge'
    Export = 'export'
    All = 'all'
    Import = 'import'
