import os
import platform

SRC_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = SRC_DIR.rstrip(os.path.basename(SRC_DIR))


def get_src_root_dir() -> str:
    """ Should be the same level as src folder (so not in "src") """
    return f'{SRC_DIR}{slash()}'


def get_root_dir() -> str:
    """ Should be the same level as CRiSp folder """
    return ROOT_DIR


def format_os(path_part):
    # On Windows, use backslash.
    if platform.system() == 'Windows':
        path_part = str(path_part).replace('/', '\\')
    else:
        path_part = str(path_part).replace('\\', '/')
    return path_part


def slash():
    return format_os('/')