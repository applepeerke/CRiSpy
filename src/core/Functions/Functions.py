# ---------------------------------------------------------------------------------------------------------------------
# Functions.py
#
# Author      : Peter Heijligers
# Description : Find the company name from a directory
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-04-03 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import base64
import os
import platform

from root_functions import SRC_DIR, ROOT_DIR


def find_company_name(basedir, companies):
    """
    Find one and only one company.
    """
    search_path = basedir.lower()
    found_company = None
    for company in companies:
        if company.lower() in search_path:
            if found_company is None:
                found_company = company
            else:
                # Multiple hits
                return '*UNKNOWN'
    return found_company


def get_icon():
    from src.gl.BusinessLayer.SessionManager import Singleton as Session
    icon = f'{Session().images_dir}Logo.png'
    icon = icon if os.path.isfile(icon) else None
    if not icon:
        return None
    with open(icon, 'rb') as f:
        result = base64.b64encode(f.read())
    return result


def strip_line(line):
    line = line.rstrip('\n')
    line = line.rstrip('\r')
    line = line.rstrip(',')
    return line.strip()


def format_os(path_part):
    # On Windows, use backslash.
    if platform.system() == 'Windows':
        path_part = str(path_part).replace('/', '\\')
    else:
        path_part = str(path_part).replace('\\', '/')
    return path_part


def slash():
    return format_os('/')


def get_src_root_dir() -> str:
    """ Should be the same level as src folder (so not in "src") """
    return f'{SRC_DIR}{slash()}'


def get_root_dir() -> str:
    """ Should be the same level as CRiSp folder """
    return ROOT_DIR
