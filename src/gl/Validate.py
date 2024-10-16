# ---------------------------------------------------------------------------------------------------------------------
# Validate.py
#
# Author      : Peter Heijligers
# Description : Validation functions
#
# - normalize_dir = validate a directory name for different platforms.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-23 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import os
import re
import string

import src.gl.UserInput as ui
from root_functions import ROOT_DIR
from root_functions import slash, format_os
from src.gl.Const import BLANK, APOSTROPHES, NONE, EMPTY, QUIT, CURRENT, CALCULATE
from src.gl.Enums import ResultCode
from src.gl.GeneralException import GeneralException
from src.gl.Result import Result

valid = False
current = False
file_chars = string.ascii_letters + string.digits

REGEX_ALPHA = re.compile(r'^\w+$')
REGEX_ALPHA_NUM = re.compile(r'^[\w _\-]+$')
REGEX_CNAME = re.compile(r'^[\w_$#@]+$')
REGEX_DIRNAME = re.compile(r'^[\w \-.:+@\\/_]+$')  # ":" is allowed for windows drive
REGEX_FILENAME = re.compile(r'^[\w \-.%+_]+$')
REGEX_VERSION = re.compile(r'^[\w.]+$')

""" 
Input validation routines 
"""


def validate_type(name, value, type):
    if value and not isinstance(value, type):
        raise ValueError(f'{name} has an invalid type.')


def validate_attribute(name, value, type):
    if value and not hasattr(type, value):
        raise ValueError(f'{name} has does not exist in the object.')


def validate_value(name, value, blank_allowed=False):
    if not value:
        return
    if isinstance(value, str) and not isValidName(value, blank_allowed):
        raise ValueError(f"{name} '{str(value)}' is not a valid name.")
    if isinstance(value, int) and value > 99999999999999:
        raise ValueError(f"{name} '{str(value)}' is not a valid int.")


def validate_dir_name(name, value):
    if value and not REGEX_DIRNAME.fullmatch(value):
        raise ValueError(f"{name} '{str(value)}' is not a valid directory.")


def validate_required(name, value):
    if isinstance(value, str) and not value:
        raise ValueError(f'{name} is required.')
    if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, dict) and not value:
        raise ValueError(f'{name} is required.')


def isValidName(name, blank_allowed=False) -> bool:
    if not name:
        return False

    if len(name) > 64:
        name = name[:64]
    # Max. 64 chars without leading/trailing hyphen
    if not REGEX_ALPHA_NUM.fullmatch(name):
        return False
    if not blank_allowed and BLANK in name:
        return False
    if name.startswith('-') or name.endswith('-'):
        return False
    return True


def isBool(value) -> bool:
    if isinstance(value, bool):
        return True
    elif isinstance(value, str):
        return True if value.lower() in ('false', 'no', 'n', 'true', 'yes', 'y') else False
    else:
        return False


def isInt(value) -> bool:
    try:
        int(value)
        return True
    except (ValueError, TypeError):
        return False


def isFloat(value) -> bool:
    try:
        float(value)
        return True
    except (ValueError, TypeError):
        return False


def isAlpha(value, maxLen=0) -> bool:
    if not _validSize(value, maxLen):
        return False
    return True if REGEX_ALPHA.fullmatch(value) else False


def isAlphaNumeric(value, maxLen=0) -> bool:
    if not _validSize(value, maxLen):
        return False
    return True if REGEX_ALPHA_NUM.fullmatch(value) else False


def isName(value) -> bool:
    if not value:
        return False
    return True if REGEX_CNAME.fullmatch(value) else False


def isDirname(value, maxLen=0) -> bool:
    if not _validSize(value, maxLen):
        return False
    return True if REGEX_DIRNAME.fullmatch(value) else False


def isHardcodedString(value) -> bool:
    if not value or not isinstance(value, str):
        return False
    value = value.strip()
    return True if value and len(value) > 1 and value[0] == value[-1] and value[0] in APOSTROPHES else False


def isFilename(value, maxLen=0) -> bool:
    if not _validSize(value, maxLen):
        return False
    return True if REGEX_FILENAME.fullmatch(value) else False


def isVersion(value, maxLen=20) -> bool:
    if not _validSize(value, maxLen):
        return False
    return True if REGEX_VERSION.fullmatch(value) else False


def isExt(value, maxLen=0) -> bool:
    if not _validSize(value, maxLen):
        return False
    if not str(value).startswith('.'):
        return False
    if not isAlphaNumeric(value[1:]):
        return False
    return True


""" 
Transformations 
"""


def normalize_dir(dir_name, create=False):
    if not dir_name:
        return EMPTY
    if create:
        if not dir_name.startswith(ROOT_DIR):
            raise GeneralException('Directory name is not within the root directory.')
        try:
            if not os.path.isdir(dir_name):
                os.makedirs(dir_name)
        except NotADirectoryError:
            raise
    return dir_name if dir_name[-1] in ('/', '\\') else f'{dir_name}{slash()}'


@DeprecationWarning
def validate_dir(dir_name, defaults_to_current=False, ask=False, create=False, compare_dir=EMPTY):
    """
    :return:
    :param dir_name: directory name
    :param defaults_to_current: If directory not exists, use current directory?
    :param ask: If directory not exists, ask for it?
    :param create: If directory not exists, create it?
    :param compare_dir: input dir must not contain output dir
    :return: dir_name: (substituted) directory name, or '' if it does not exist
    """
    global valid, current
    valid = False

    while not valid:
        valid = True
        current = False
        # Get a valid directory name
        dir_name = _substitute_current_dir(dir_name)  # "c" can be input
        if not current:
            dir_name = _format_dir(_get_existing_dir(dir_name, defaults_to_current, ask, create))
        # To prevent loop, when output files are generated in input directory:
        # input dir must not start with compare dir
        if not str(dir_name).lower() == QUIT and not compare_dir == EMPTY:
            if _format_dir(compare_dir).startswith(str(dir_name)):
                dir_name_invalid = dir_name
                dir_name = QUIT
                if ask:
                    dir_name = ui.ask("Output directory '" + str(dir_name_invalid) +
                                      "' must not be part of the input directory. Please specify a valid directory "
                                      "(c=current, q=quit): ")
        if str(dir_name).lower() == QUIT:
            dir_name = QUIT
            valid = True
    if dir_name == QUIT and not ask:
        dir_name = None
    return dir_name


def _get_existing_dir(dir_name, defaults_to_current=True, ask=False, create=False):
    while not os.path.exists(dir_name):
        try:
            dir_name = _get_dir_name(dir_name, defaults_to_current, ask, create)
        except NotADirectoryError:
            return QUIT
        if not ask:
            if not os.path.exists(dir_name):
                dir_name = QUIT
            break
    return dir_name


def _get_dir_name(dir_name, defaults_to_current=True, ask=False, create=False):
    if ask:
        dir_name = ui.ask("Directory '" + dir_name +
                          "' does not exist. Please specify a valid directory (c=current, q=quit): ")
    # If not interactive, ALWAYS return something valid to prevent a loop.
    else:
        # Use current directory if it does not exist.
        if defaults_to_current:
            dir_name = CURRENT
        else:
            if create:
                try:
                    os.makedirs(dir_name)
                except NotADirectoryError:
                    raise
    dir_name = _substitute_current_dir(dir_name)
    return dir_name


def _substitute_current_dir(dir_name):
    global current
    if not dir_name:
        return EMPTY

    if dir_name.lower() == CURRENT or dir_name in ['/', './', '/.', '\\']:
        current = True
        dir_name = _format_dir(os.getcwd())
    if str(dir_name).startswith('.'):
        dir_name = _format_dir(os.getcwd() + dir_name[1:])
    return dir_name


def _format_dir(dir_name):
    if not dir_name:
        return EMPTY
    # Append a directory separator if not 'q' and not already present.
    if not (dir_name.lower() == QUIT or dir_name == EMPTY or dir_name.endswith('/')
            or dir_name.endswith('\\')):
        dir_name += '/'
    return format_os(dir_name)


def toBool(value, default=None) -> bool:
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        if value.lower() in ('false', 'no', 'n'):
            return False
        elif value.lower() in ('true', 'yes', 'y'):
            return True
    if not value and default is not None:
        return default
    raise GeneralException(f"Unsupported boolean value '{value}'")


def toFloat(value, default=False) -> float:
    if isinstance(value, float):
        return value
    elif isinstance(value, str):
        try:
            value = float(value)
        except (ValueError, TypeError):
            return False
        return value
    else:
        return default


def strictNone(value):
    return None if value is None or value == NONE else value


def enforce_valid_name(name):
    # re.sub(r'[^\x00-\x7F]+', '_', name)
    out = []
    for i in name:
        if i not in file_chars:
            out.append('_')
        else:
            out.append(i)
    out_name = ''.join(out)
    if len(out_name) > 64:
        out_name = out_name[:64]
    return out_name


def validate_text(text, ask=False, length=64):
    if not text:
        return EMPTY

    while len(text) > length:
        # Max. 64 chars
        if ask:
            text = ui.ask("Text '" + text + "' is too long. Please specify a valid text (q = quit): ")
            if text == QUIT or text == EMPTY:
                break
        else:
            text = text[:length]
            break
    return text


def select_item(class_name, dft, question, list_entries):
    """
    Select a Key-value item
    :param class_name: List name
    :param dft: default key
    :param question:
    :param list_entries:
    :return: Result class
    """
    result = Result()
    result.code = ResultCode.Error
    if dft == EMPTY:
        dft_value = [EMPTY, EMPTY]
    else:
        dft_value = [dft, EMPTY]
    result.result_value = dft_value
    result.text = dft

    while not result.code == ResultCode.Ok:
        input_raw = input(question + " (dft='" + dft + "', q=quit): ")
        input_lc = input_raw.lower()
        if input_lc == QUIT:
            result.code = ResultCode.Cancel
            result.text = "Processing _has been canceled by the user."
            break
        if input_lc == EMPTY:
            input_raw = dft
            result.result_value = dft_value
            result.code = ResultCode.Ok
        else:
            result = check_item(class_name, input_lc, list_entries)
        if not result.code == ResultCode.Ok:
            print(class_name + " '" + input_raw + "' is not supported. Please try again.")
    return result


def check_item(class_name, item, list_entries, default=EMPTY) -> Result:
    result = Result()
    result.code = ResultCode.Cancel

    # Default = EMPTY
    if not item or item == default:
        result.text = default
        result.result_value = default
        result.code = ResultCode.Ok
    # *SPECIAL values [Calculate]
    elif item == CALCULATE:
        result.text = item
        result.result_value = item
        result.code = ResultCode.Ok
    else:
        # Check list
        for entry in list_entries:
            if item.lower() == entry.lower():
                result.text = entry
                # result.result_value = [entry, entry]
                result.result_value = entry
                result.code = ResultCode.Ok
                break
    # Not found
    if not result.code == ResultCode.Ok:
        result.result_value = EMPTY
        result.text = "'" + item + "' does not exist in '" + class_name + "'."
    return result


def valid_date_format(date) -> bool:
    return True if date and len(date) == 10 and date[4] == '-' and date[7] == '-' else False


def _validSize(value, maxLen) -> bool:
    if not value or 0 < maxLen < len(value):
        return False
    return True
