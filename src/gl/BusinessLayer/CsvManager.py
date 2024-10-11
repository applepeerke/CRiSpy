# ---------------------------------------------------------------------------------------------------------------------
# DataManager.py
#
# Author      : Peter Heijligers
# Description : Manage csv table data
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-04 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import csv
import os
import traceback

from src.gl.BusinessLayer.ErrorControl import ErrorType
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrorControl
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Validate import isDirname, isInt

EMPTY = ''
PGM = 'CsvManager'


class CsvManager(object):
    """
    Manage business data in .csv files
    """

    def __init__(self):
        self._file_name = EMPTY
        self._data_path = EMPTY
        self._excluded_extensions = []

    @property
    def file_name(self):
        return self._file_name

    @file_name.setter
    def file_name(self, value):
        self._file_name = value

    def get_rows(self, include_header_row=False, where=None, data_path=None, include_empty_row=True) -> list:
        """
        Read rows from disk
        :return: list
        """
        method = 'get_rows'
        rows = []
        if not data_path:
            data_path = Session().import_dir + self.file_name

        # Validate path
        if not os.path.isfile(data_path):
            self._error_control(method, f"File '{data_path}' does not exist.", severity=ErrorType.Warning)
            return []
        if not isDirname(data_path):
            self._error_control(method, f"Filename '{data_path}' is not valid.", severity=ErrorType.Warning)
            return []

        index = 0
        try:
            with open(data_path, encoding='utf-8-sig') as csvFile:
                csv_reader = csv.reader(csvFile, delimiter=';',
                                        quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for row in csv_reader:
                    if include_header_row or index > 0:
                        # Where clauses, if filled and no match: continue.
                        valid = True
                        if where is not None:
                            for key, value in where.items():
                                if value != EMPTY and row[key].lower() != value.lower():
                                    valid = False
                        # Optionally skip empty rows
                        if valid and not include_empty_row:
                            valid = False
                            for cell in row:
                                if cell is not EMPTY:
                                    valid = True
                                    break
                        if valid:
                            rows.append(row)
                    index += 1
        except csv.Error:
            self._error_control(method, f"csv error in row {str(index + 1)}  of '{data_path}':")
            # self._error_control(method, traceback.format_exc())
        except UnicodeDecodeError as e:
            self._error_control(method, f"csv error in row {str(index + 1)}  of '{data_path}': {e}\n "
                                        f'(e.g. 0xd5 means an invalid apostroph, '
                                        f"may be copied to 'answer' column from an email...)\n")
            # self._error_control( method, traceback.format_exc() )
        return rows

    def get_first_row(self, data_path=None, delimiter=';') -> list:
        method = 'get_first_row'
        if not data_path:
            self._error_control(method, f'Parameter data_path is required.')
            return []
        try:
            with open(data_path, encoding='utf-8-sig') as csvFile:
                data_reader = csv.reader(csvFile, delimiter=delimiter, quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for row in data_reader:
                    return row
        except (IOError, IndexError, csv.Error):
            self._error_control(method, 'Error in "' + data_path + '":')
            self._error_control(method, traceback.format_exc())
            return []

    def write_rows(self, rows, col_names=None, open_mode='a', data_path=None, add_id=True) -> bool:
        """
        Write rows to disk
        """
        if not rows:
            return True

        try:
            first = True
            with open(data_path, open_mode) as csvFile:
                csv_writer = csv.writer(
                    csvFile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
                for row in rows:
                    if col_names is not None and first:
                        first = False
                        header = ['Id'] if add_id else []
                        header.extend(col_names)
                        csv_writer.writerow(header)
                    csv_writer.writerow(row)
            return True
        except csv.Error:
            self._error_control('write_rows', traceback.format_exc())
            return False

    def get_row_set(self, filters, data_path, add_header_row=False):
        """
        Get filtered csv file rows.
        You may apply 1-n selections.
        A filter is 'Passed' when the values of all filtered columns match with those in the filter.
        :param add_header_row:
        :param filters: dictionary with rows that must contain a value. Filters are in an AND-relation.
        :param data_path:
        :return: passed rows list
        """
        method = 'get_row_set'
        rows_out = []

        # Check input
        if not isinstance(filters, dict):
            self._error_control(
                method, 'Parameter "selections" is not a dict')

        if not os.path.isfile(data_path):
            self._error_control(
                method, f"Parameter 'datapath' is not a file: '{data_path}'")

        # Go!
        first = True
        filter_on_colno = {}

        try:
            with open(data_path) as csvFile:
                data_reader = csv.reader(
                    csvFile, delimiter=';',
                    quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for row in data_reader:
                    # 1st row: Check filter
                    if first:
                        first = False
                        filter_on_colno = self._set_filter(row, filters)
                        if add_header_row:
                            rows_out.append(row)
                            continue

                    # Apply selections
                    passed = True
                    # Read selections
                    for col_no, col_value in filter_on_colno.items():
                        # If a row value does not match the requested column value: next row.
                        if row[col_no] != str(col_value):
                            passed = False
                            break
                    if passed:
                        rows_out.append(row)
        except csv.Error:  # Error: field larger than field limit (131072)
            self._error_control(method, traceback.format_exc())
        finally:
            return rows_out

    def _set_filter(self, header_row, filter_dict: dict) -> dict:
        """
        Convert filter dictionary to a filter on column number
        """
        result = {}
        for k, v in filter_dict.items():
            if isInt(k):
                if k < 0 or k > len(header_row) - 1:
                    self._error_control('_set_filter', f"Column '{k}' does not exit in header row '{header_row}'")
                result[k] = filter_dict[k] = v  # Copy
            else:
                try:
                    col_no = header_row.index(k)
                    result[col_no] = v
                except ValueError:
                    self._error_control('_set_filter', f"Column '{k}' does not exit in header row '{header_row}'")
        return result

    @staticmethod
    def len(data_path):
        row_count = 0
        try:
            with open(data_path) as csvFile:
                reader = csv.reader(csvFile, delimiter=";")
                data = list(reader)
                row_count = len(data)
        except IOError:
            row_count = 0
        finally:
            return row_count

    def get_column(self, col_no=0, unique=False, data_path=EMPTY, title=None):
        """
        Get a column from a csv file, only the datat without the header.
        :param col_no:
        :param unique: only distinct values
        :param data_path: input csv file
        :param title: get column based on column heading
        :return: the column, i.e. list of values
        """
        column = []
        include_header_row = True if title else False
        rows = self.get_rows(data_path=data_path, include_header_row=include_header_row)

        if not rows or not rows[0]:
            return []

        # Get colno
        if title:
            try:
                col_no = -1
                header = rows[0]
                for i in range(0, len(header)):
                    if header[i].lower() == title.lower():
                        col_no = i
                        break
                if col_no == -1:
                    return []
            except (ValueError, IndexError):
                self._error_control('get_column title ended in error', traceback.format_exc())

        # If last column(s) is/are empty, less columns are retrieved, so then column may not exist.
        if col_no >= len(rows[0]):
            return []

        try:
            first = True
            for row in rows:
                # Skip 1st row if 1st row is the header
                if first:
                    first = False
                    if title:
                        continue
                if not unique or row[col_no] not in column:
                    column.append(row[col_no])
        except IndexError:
            self._error_control('get_column ended in error', traceback.format_exc())
        finally:
            return column

    @staticmethod
    def _error_control(routine, error_text=EMPTY, severity=ErrorType.Error):
        ErrorControl().add_line(severity, PGM + '.' + routine + ': ' + error_text)
