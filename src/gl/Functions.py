import datetime
import fnmatch
import hashlib
import ntpath
import os
import platform
import string
import time

from root_functions import ROOT_DIR
from src.core.Functions.Functions import slash, format_os
from src.gl.Const import EMPTY, MAX_LOOP_COUNT, NONE, APOSTROPHES, BLANK, DB_LIST_REPRESENTATION_SUBSTITUTE, APP_NAME, \
    LC, WORD_CHARS, NUM
from src.gl.Enums import ApplicationTypeEnum

path_head = EMPTY
alphanum = string.ascii_letters + string.digits
loop_count = 0
suffix_p = None
date_zeroes = '0000000000'


def sanitize_none(value):
    return None if value == NONE else value


def file_as_bytes(file):
    with file:
        return file.read()


def get_int(value):
    if value == EMPTY:
        return 0
    try:
        return int(value)
    except ValueError:
        return -1


def get_file_hash(path):
    try:
        if os.path.isfile(path):
            return hashlib.sha256(file_as_bytes(open(path, 'rb'))).hexdigest()
        else:
            return '*NOT_A_FILE*'
    except IOError:
        return '*IOERROR'


def replace_root_in_path(path, search_string=None):
    root = get_root_in_path(search_string)
    if root and path and path.startswith(root):
        return path.replace(root, EMPTY)
    return path


def get_root_in_path(search_string=None):
    if not search_string:
        search_string = f'{slash()}{APP_NAME}{slash()}'
    current_path = os.path.dirname(os.path.realpath(__file__))
    index = current_path.find(search_string)
    return current_path[:index] if index > 0 else EMPTY


def sanitize_text_to_alphanum_and_underscore(text: str, replace_by: str = "_", special_chars=None) -> str:
    try:
        if not text:
            return EMPTY
        c_prv = EMPTY
        for c in text:
            if c in alphanum or (special_chars and c in special_chars):
                continue
            if c_prv == replace_by:  # previous was "_": ignore
                text = str.replace(text, c, EMPTY)
            else:
                text = str.replace(text, c, replace_by)

        # Replace multiple '_' by single '_'
        if replace_by and len(replace_by) == 1:
            text = text.strip(replace_by)
            text_out = []
            for c in text:
                if c != replace_by or c_prv != replace_by:
                    text_out.append(c)
                c_prv = c
            if text_out:
                text = "".join(str(x) for x in text_out)
    except TypeError:  # Not a string: pass
        pass
    finally:
        return text


def strip_bytes_and_crlf(line):
    # Remove byte presentation
    if line[0] == "b" and line[1] in APOSTROPHES:
        line = line[2:len(line) - 1]
    # Remove CRLF
    if line.endswith('\\n'):
        line = line[:len(line) - 2]
    if line.endswith('\\r'):
        line = line[:len(line) - 2]
    return line


def path_leaf(path) -> (str, str):
    """
    Get last leaf in a path. Also remember the head.
    """
    global path_head
    if not path:
        return EMPTY, EMPTY
    if path[-1] in ['/', '\\']:
        path = path[:-1]
    path_head, tail = ntpath.split(path)
    return path_head, tail or ntpath.basename(path_head)


def path_leaf_only(path):
    """
    Get last leaf in a path.
    """
    if not path:
        return EMPTY
    if path.endswith(slash()):
        path = path[:-1]
    head, tail = ntpath.split(path)
    return tail


def remove_surrounding_quotes(text):
    text = text.strip()
    if not text:
        return text
    if text[0] == text[-1] and text[0] in APOSTROPHES:
        return text[1:-1]
    return text


def remove_trailing_comment(text):
    p = text.find('#')
    if p == -1:
        return text
    return text[:p].rstrip()


def remove_color_code(text):
    if not text.isprintable() and not text == '\n':
        out = []
        for i in range(len(text)):
            if text[i].isprintable() or text[i] == '\n':
                out.append(text[i])
            else:
                out.append(EMPTY)
        text = EMPTY.join(out)

    if '[' in text:
        text = text.replace('[0m', EMPTY)
        text = text.replace('[31m', EMPTY)
        text = text.replace('[32m', EMPTY)
        text = text.replace('[33m', EMPTY)
        text = text.replace('[34m', EMPTY)
        text = text.replace('[35m', EMPTY)
        text = text.replace('[36m', EMPTY)
    return text


def get_word_rate(token) -> int:
    """
    A string of more than 2 different alpha chars is considered a "word".
    If 5 consecutive same characters are found it is considered not a token (e.g. "============+======")
    Return the rate of characters consisting of words.
    """
    i, this_word_length, word_count, total_word_length, same_count = 0, 0, 0, 0, 0
    first = True
    token_type, p_token, p_token_type = EMPTY, EMPTY, EMPTY

    while i < len(token):
        # UC after a LC is a break.
        token_type = 'LC' if token[i] in LC else '!LC'
        if first:
            first = False
            p_token = token[i]
            p_token_type = token_type

        # Same token.
        if token[i] == p_token:
            same_count += 1
            if token[i] in WORD_CHARS:
                this_word_length += 1
            if same_count > 5:
                return 100  # > 5 consecutive same chars: no token
        else:
            same_count = 0
            # break: when special char encountered or at a transition of LC to UC v.v.
            if token[i] not in WORD_CHARS or token_type != p_token_type:
                p_token_type = token_type
                if this_word_length > 2:
                    word_count += 1
                    total_word_length += this_word_length
                    this_word_length = 0
            else:
                this_word_length += 1
        p_token = token[i]
        i += 1
    # Last time
    if this_word_length > 2:
        word_count += 1
        total_word_length += this_word_length

    rate = (total_word_length / len(token)) * 100 if len(token) > 0 else 0
    return rate


def get_digit_rate(token) -> int:
    if not token:
        return 100

    i, num_count = 0, 0
    token_lc = token.lower()

    while i < len(token_lc):
        if token_lc[i] in NUM:
            num_count += 1
        i += 1

    rate = (num_count / len(token)) * 100
    return int(rate)


def move_file(from_path, to_path) -> bool:
    if not os.path.isfile(from_path):
        return False
    if os.path.isfile(to_path):
        os.remove(to_path)
    try:
        os.rename(from_path, to_path)
    except OSError as e:
        print(f'{__name__}: {e.args[0]}')
        return False
    return True


def remove_empty_folders(path, removeRoot=True):
    if not os.path.isdir(path):
        return

    # remove empty subfolders
    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                remove_empty_folders(fullpath)

    # if folder empty, delete it
    files = os.listdir(path)
    if len(files) == 0 and removeRoot:
        # print(f'Removing empty folder: {path}')
        os.rmdir(path)


def loop_increment(suffix) -> bool:
    global loop_count, suffix_p
    if suffix != suffix_p:
        suffix_p = suffix
        loop_count = 0
    loop_count += 1
    if loop_count > MAX_LOOP_COUNT:
        print(f'{suffix}: Max loop count reached.')
        return False
    return True


def list_to_string(values: list) -> str:
    if not values:
        return EMPTY
    # Already a stringed list?
    if is_stringed_list(values):
        return str(values[1:-1])  # Truncate []
    if type(values) is list or type(values) is set:
        return ', '.join(values)
    return str(values)


def is_stringed_list(value) -> bool:
    return True if type(value) is str and len(value) > 2 and value[0] == '[' and value[-1] == ']' else False


def stringed_list_to_list(value) -> []:
    result = []

    if is_stringed_list(value):
        values = value.strip('][').split(', ')
        for v in values:
            for s in DB_LIST_REPRESENTATION_SUBSTITUTE:
                v = v.replace(s, EMPTY)
            result.append(v)
    return result


def find_file(name, path):
    _validate_path(path)
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return None


def find_files(name, path):
    _validate_path(path)
    paths = []
    for root, dirs, files in os.walk(path):
        if name in files:
            paths.append(os.path.join(root, name))
    return paths


def find_files_for_type(file_type, basedir=os.curdir):
    """
    Return all file paths matching the specified file type in the specified base directory (recursively).
    """
    _validate_path(basedir)
    for path, dirs, files in os.walk(os.path.abspath(basedir)):
        for filename in fnmatch.filter(files, file_type):
            yield os.path.join(path, filename)


def find_files_in_path(path):
    _validate_path(path)
    for (root, dirs, dir_files) in os.walk(path):
        return [f"{path}{format_os('/')}{file}" for file in dir_files]
    return []


def _validate_path(path_or_dir):
    if not path_or_dir.startswith(ROOT_DIR):
        raise ValueError('Directory name is not within the root directory.')


def strip_crlf(line) -> str:
    # NB:  rstrip('\\r\\n') also removes last "n"!
    if not line:
        return line
    if line.endswith('\\n'):
        line = line[:-2]
    if line.endswith('\\r'):
        line = line[:-2]
    return line


def creation_date(path_to_file) -> str:
    """
    Try to get the date that a file was created, falling back to when it was
    last modified if that isn't possible.
    See http://stackoverflow.com/a/39501288/1709587 for explanation.
    """
    if not os.path.isfile(path_to_file):
        return EMPTY
    if platform.system() == 'Windows':
        ts = os.path.getctime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            ts = stat.st_birthtime
        except AttributeError:
            # We're probably on Linux. No easy way to get creation dates here,
            # so we'll settle for when its content was last modified.
            ts = stat.st_mtime
    crt_date = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d')
    return crt_date


def format_date(date: str, input_date_format=None, output_separator='-') -> str:
    """
    Requirements: Input is formatted string, where year is in yyyy format. Blank can not be a separator (EMPTY can).
    Return: yyyy-mm-dd.
    """
    # Validate before
    if not date or input_date_format not in ('YMD', 'DMY', 'MDY'):
        return EMPTY
    # If "date time", remove the "time" part
    if len(date) > 10:
        if ':' in date:
            p = date.find(BLANK)
            if p:
                date = date[:p]
        if len(date) > 10:
            return EMPTY

    # Get the 2 positions of date separators (like '/' or '-')
    sep_index = [i for i in range(len(date) - 1) if date[i] != BLANK and not date[i].isdigit()]
    # If no separators, add them
    if not len(sep_index) == 2:
        if sep_index or len(date) != 8:
            return EMPTY
        if input_date_format == 'YMD':
            return f'{date[:4]}{output_separator}{date[4:6]}{output_separator}{date[6:]}'
        elif input_date_format == 'DMY':
            return f'{date[4:8]}{output_separator}{date[2:4]}{output_separator}{date[:2]}'
        else:  # MDY
            return f'{date[4:8]}{output_separator}{date[:2]}{output_separator}{date[2:4]}'

    # Get uniform date elements
    E1 = date[:sep_index[0]].lstrip()
    E2 = date[sep_index[0] + 1:sep_index[1]]
    E3 = date[sep_index[1] + 1:].rstrip()

    if input_date_format == 'YMD':
        YY = E1
        MM = _pad_zeroes(E2)
        DD = _pad_zeroes(E3)
    elif input_date_format == 'DMY':
        YY = E3
        MM = _pad_zeroes(E2)
        DD = _pad_zeroes(E1)
    else:  # MDY
        YY = E3
        MM = _pad_zeroes(E1)
        DD = _pad_zeroes(E2)
    # Validate after
    if not len(YY) == 4:
        return EMPTY
    return f'{YY}{output_separator}{MM}{output_separator}{DD}'


def timestamp_from_string(date_Y_m_d, time_H_M_S=None):
    if time_H_M_S:
        time_stamp = time.mktime(
            datetime.datetime.strptime(f'{date_Y_m_d} {time_H_M_S}', '%Y-%m-%d %H:%M:%S').timetuple())
    else:
        time_stamp = time.mktime(
            datetime.datetime.strptime(f'{date_Y_m_d}', '%Y-%m-%d').timetuple())
    return time_stamp


def _pad_zeroes(element, length=2) -> str:
    if len(element) >= length:
        return element
    no_of_zeroes = length - len(element)
    return f'{date_zeroes[:no_of_zeroes]}{element}'


def get_names_from_line(line, return_too=True) -> set:
    """ To get class names """
    names = set()
    name = []
    r = line.find('->')
    for i in range(max(r, len(line))):
        if line[i].isalnum():  # Alphanum: Add char to word
            name.append(line[i])
        else:  # End of Word: Add word to words
            if name:
                names.add(EMPTY.join(name))
                name = []
    # last time
    if name:
        names.add(EMPTY.join(name))
    return names


def soph_empty_list(value: list) -> list:
    return [] if value == [''] else value


def is_internet_facing(application_type: ApplicationTypeEnum) -> bool:
    return True if application_type in (
        ApplicationTypeEnum.Any,
        ApplicationTypeEnum.WebApp,
        ApplicationTypeEnum.Frontend) else False
