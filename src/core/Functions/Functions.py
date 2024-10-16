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
import os
import platform

from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Const import SPECIAL_CHARS
from src.gl.Functions import sanitize_text_to_alphanum_and_underscore
from src.utils.csv_to_html import CsvToHtml

csv = CsvManager()


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


def get_csv_as_txt(path, sanitize=True) -> list:
    if not os.path.isfile(path):
        return []
    rows = csv.get_rows(include_header_row=True, data_path=path)
    lines = [', '.join(row) for row in rows]
    return lines if not sanitize else \
        [sanitize_text_to_alphanum_and_underscore(line, special_chars=SPECIAL_CHARS) for line in lines]


def get_csv_as_html(path, sanitize=True) -> str:
    if not os.path.isfile(path):
        return '<html><body>File was not found.</body></html>'
    rows = csv.get_rows(include_header_row=True, data_path=path)
    csv2html = CsvToHtml()
    return csv2html.start(rows, sanitize=sanitize)
