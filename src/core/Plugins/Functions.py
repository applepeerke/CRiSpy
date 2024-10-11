import os

from src.core.BusinessLayer.Scanner import Scanner
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Enums import Color
from src.gl.Functions import path_leaf
from src.gl.Validate import normalize_dir


def find_filename_from_parent_dir(filename) -> list:
    """
    Find all filenames from the input_dir parent.
    Purpose is to find configuration files like requirements.txt,  requirements_base.txt or pom.xml.
    Returns the full paths.
    """
    # Get configuration dir, should be left to the input folder
    basename, ext = os.path.splitext(filename)
    data_dir, _ = path_leaf(Session().input_dir)
    data_dir = normalize_dir(data_dir)
    if not ext or not data_dir:
        return []

    scanner = Scanner()
    scanner.find_files(f'*{ext}')
    return [p for p in scanner.find_files(f'*{ext}', basedir=data_dir)
            if p and os.path.basename(p).startswith(basename)]


def completion_message_of_field_analysis(class_type, class_name, field_count: int, vulnerable_field_count: int) -> str:
    text = f'{Color.RED}vulnerable' if vulnerable_field_count > 0 else f'{Color.GREEN}sane'
    cause = f'{field_count} fields detected.'
    if vulnerable_field_count == 0:
        pass
    elif vulnerable_field_count == field_count:
        cause = f'{cause} All are sane.' if vulnerable_field_count == 0 \
            else f'{cause} All are vulnerable.'
    else:
        cause = f'{cause} {field_count - vulnerable_field_count} are sane.'
    return f'{class_type} {class_name} is {text}{Color.NC}. {cause}'


def bullet():
    return f'\n{Color.BLUE}      o {Color.NC}'
