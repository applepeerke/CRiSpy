# ---------------------------------------------------------------------------------------------------------------------
# FindProject.py
#
# Author      : Peter Heijligers
# Description : Find the project name from a directory
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-04-02 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import os
import string

from root_functions import ROOT_DIR
from src.gl.Const import EMPTY
from src.gl.Enums import *
from src.gl.Functions import path_leaf, get_word_rate, sanitize_text_to_alphanum_and_underscore
from root_functions import slash
from src.gl.GeneralException import GeneralException

PGM = 'FindProject'
slash = slash()


def find_project_name(basedir, language=None, pid_names=None, company_name=None) -> str:
    """
    1. Find root path.
        1. Find paths containing "src".
        2. If not found, try to find_file paths containing file extensions like ".sln".
        3. If not found, try to find_file paths containing file names like "_init_.py".
        4. If not found, use the specified basedir.
        5. If many found, Select most significant (top level) preceding dir.
    2. Find project_name. Go back in path until ako project name is found.
    """
    dir_names = []

    if not basedir:
        return EMPTY

    project_ext_found = False
    dir_names.extend(_find_dir_names_by_leaf(basedir, 'src'))

    # Not found: Search by project extension
    if len(dir_names) == 0:
        if language is None:
            dir_names.extend(_find_dir_names_by_leaf(basedir, '.xcodeproj', leafType=LeafType.Ext))
            dir_names.extend(_find_dir_names_by_leaf(basedir, '.csproj', leafType=LeafType.Ext))
        elif language == Language.iOS:
            dir_names.extend(_find_dir_names_by_leaf(basedir, '.xcodeproj', leafType=LeafType.Ext))
        elif language == Language.NET:
            dir_names.extend(_find_dir_names_by_leaf(basedir, '.csproj', leafType=LeafType.Ext))
    if len(dir_names) > 0:
        project_ext_found = True

    # Not found: Search by project start program
    if len(dir_names) == 0:
        if language is None:
            dir_names.extend(_find_dir_names_by_leaf(basedir, 'main.m'))
            dir_names.extend(_find_dir_names_by_leaf(basedir, '_init_.py'))
        elif language == Language.iOS:
            dir_names.extend(_find_dir_names_by_leaf(basedir, 'main.m'))
        elif language == Language.Python:
            dir_names.extend(_find_dir_names_by_leaf(basedir, '_init_.py'))

    # Not found: Use specified basedir
    if len(dir_names) == 0:
        found_dir = basedir
    else:
        # If many found, select shortest path
        found_dir = None
        if len(dir_names) == 1:
            found_dir = dir_names[0]
        else:
            for dir_name in dir_names:
                if found_dir is None or len(dir_name) < len(found_dir):
                    found_dir = dir_name
        if found_dir is None:
            return EMPTY

        # Project extension found (e.g. csproj): Leaf contains the project name!
        if project_ext_found:
            basename = os.path.basename(found_dir)
            file_name, file_extension = os.path.splitext(basename)
            return _sophisticate_project_name(file_name, company_name=company_name)

    return _try_to_get_project_name(found_dir, ['(', '-'], pid_names, company_name)


def _try_to_get_project_name(found_dir, search_strings: list, pid_names: list, company_name) -> str:
    """
    Go back in path until ako project name is found. i.e. one word or containing a "-" or "_"
    """
    # A. Project names surrounded by delimiters
    path_head = found_dir
    leaf = 'dummy'
    while leaf:
        path_head, leaf = path_leaf(path_head)
        if 2 < len(leaf) < 64:
            # pid_names e.g. [[161, DE Mobile], [162, Test]]
            if pid_names and len(pid_names) > 0 and len(pid_names[0]) > 1:
                for project in pid_names:
                    if leaf.startswith(str(project[0])):
                        return project[1]
            else:
                # search strings ("-" or "_")
                for s in search_strings:
                    if s in leaf and not leaf.startswith(s):
                        project_name = _sophisticate_project_name(leaf, company_name=company_name)
                        if project_name:
                            return project_name

    # B. One-word project names.
    # If "src", try directly before the "src".
    path_head = found_dir
    path_head, leaf = path_leaf(path_head)
    if leaf.lower() == 'src':
        path_head, leaf = path_leaf(path_head)

    # One of the delimiters must not be present in the leaf.
    if not any(x in leaf for x in search_strings):
        project_name = _sophisticate_project_name(leaf, company_name=company_name)
        if project_name:
            return project_name

    return EMPTY


def _sophisticate_project_name(leaf, delim=' - ', company_name=None):
    """
    Remove the pid/version number and everything from 2nd '-' or '_'.
    Examples:
    20190101 - ETD - HM                         ETD_HM
    20190101 - IR - DE-Mobile                   DE_Mobile
    20190101 - B - Capri - NiceNL - Pid 198     Capri_NiceNL
    ngc-collar_V001                             ngc_collar
    ngc-collar-v.18.0.4                         ngc_collar
    """

    if not leaf:
        return None

    # Remove company name, numbers
    if company_name:
        leaf.replace(company_name, EMPTY)

    leaf = _remove_numbers(leaf)
    # If number was version, remove single char left-over (like "my-project-name-v1.18").
    if len(leaf) > 2 and leaf[-2] in ('-', '_'):
        leaf = leaf[:-2]

    if leaf:
        leaf = leaf.strip(' -_()')  # Skip surrounding tokens
        if get_word_rate(leaf) < 20:
            return sanitize_text_to_alphanum_and_underscore(leaf)

    if not leaf:
        return None

    # If delimiter (" - ") exist, get the 1st match

    if delim:
        leaf = '_'.join(
            [w for w in leaf.split(delim)
             if w[0] in string.ascii_letters and len(w) > 2 and not w.lower().startswith('pid')]
        )

    # c. Remove non-alphanum, then set lo LC
    if leaf:
        leaf = sanitize_text_to_alphanum_and_underscore(leaf)
        return leaf.lower()

    return None


def sophisticate_path_name(path, search_string=None, line_no=None) -> str:
    """
    Go max_count leaflets back in path or until search string is found.
    """
    if not path or not search_string:
        return path
    result = None
    leaf = 'dummy'
    found = False
    count = 0
    path = path.rstrip(slash)
    path_head = path
    while leaf and count < 100:
        count += 1
        path_head, leaf = path_leaf(path_head)
        result = f'{leaf}{slash}{result}' if result else leaf
        if str(search_string) in leaf.replace('-', '_'):
            found = True
            break
    if found:
        path = f'..{slash}{result}{slash}'
    if line_no:
        if path and path.endswith(slash):
            path = path[:-1]
        path = f'{path}:{line_no}'
    return path


def _find_files(basedir=os.curdir):
    """
    Return all file paths (recursively).
    """
    if not basedir.startswith(ROOT_DIR):
        raise GeneralException('Directory name is not within the root directory.')
    for path, dir_name, file_names in os.walk(os.path.abspath(basedir)):
        for file_name in file_names:
            yield os.path.join(path, file_name)


def _find_dir_names_by_leaf(base_dir, leaf, leafType=LeafType.Name, allowMany=True) -> list:
    """
    List directories by leaf(s) (recursively)
    """
    dir_names = []

    # Validate input
    if leaf is None or leaf == EMPTY:
        return []

    for file_path in _find_files(base_dir):
        basename = os.path.basename(file_path)
        # Dir name found (e.g. 'src'): append path
        if leafType == LeafType.Name and basename.lower() == leaf:
            dir_names.append(file_path)
            if not allowMany:
                break
        # File extension found (e.g. '.sln'): append path
        elif leafType == LeafType.Ext:
            if basename.lower().endswith(leaf):
                dir_names.append(file_path)
                if not allowMany:
                    break
    return dir_names


def _remove_numbers(input_name) -> str:
    """
    Remove numbers.
    """
    output_name = []
    i = 0
    length = len(input_name)
    while i < length:
        while i < length and input_name[i] == '0123456789.,':
            i += 1
        if i < length:
            output_name.append(input_name[i])
        i += 1
    return ''.join(output_name)


def get_project_name_from_file_name(file_name) -> str:
    # myProjectName_Vnnn.csv
    result = EMPTY
    length = len(file_name)
    if length > 10 and file_name[length - 4:] == '.csv' and file_name[length - 9:length - 7] == '_V':
        result = _sophisticate_project_name(file_name[:length - 9], delim=EMPTY)
    return result
