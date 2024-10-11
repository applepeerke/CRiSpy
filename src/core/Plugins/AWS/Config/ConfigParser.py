# ---------------------------------------------------------------------------------------------------------------------
# ConfigParser.py
#
# Author      : Peter Heijligers
# Description : Parse Config files, output to Csv
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-05-16 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import csv
import os
from pathlib import Path

from root_functions import ROOT_DIR
from src.core.DataLayer.Enums import ConfigFileType
from src.core.Plugins.Const import CONFIGS_FOUND
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import CSV_EXT, EMPTY, MAX_CONFIG_FILE_SIZE_IN_BYTES
from src.gl.Enums import Language, Color, MessageSeverity
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message

csvm = CsvManager()
session = Session()


class ConfigParser(object):

    @property
    def file_type(self):
        return self._file_type

    @property
    def messages(self):
        return self._messages

    @property
    def files_count(self):
        return self._files_count

    @property
    def blacklist(self):
        return self._blacklist

    def __init__(self, file_type):
        self._file_type = file_type
        self._messages = []
        self._rows = []
        self._blacklist = set()
        self._files_count = 0

    def run(self) -> list:
        """
        Parse all file paths matching the specified file type in the specified base directory (recursively).
        In case of Json the file is inspected to evaluate if it is Json.
        """
        self._messages = []

        # Validation
        if not session:
            return [f'{__name__}: Session is required.']

        if self._file_type not in ConfigFileType.values:
            self._messages.append(Message(
                f"{__name__}: {Color.GREEN}Unsupported file type {Color.BLUE}'{self._file_type}'{Color.NC}",
                MessageSeverity.Error))
            return self._messages

        excluded_file_extensions = csvm.get_column(
            0, data_path=f'{session.plugins_dir}Exclude_configuration_file_ext.csv')

        # In case of Json the file is inspected to evaluate if it is Json.
        if self._file_type == ConfigFileType.Json:
            file_ext = None
        else:
            file_ext = f'.{self._file_type}'

        # Yield end parse files
        self._rows = []

        for file_path in self._find_files(session.input_dir, file_ext):
            self._files_count += 1
            self._rows.extend(self._try_and_get_file_data(file_path, file_ext, excluded_file_extensions))

        # Output
        self._write_lines(self._rows, self.get_output_file(self._file_type))

        if self._blacklist:
            self._messages.append(Message(f'{Color.GREEN}File types{Color.ORANGE} {self._blacklist} '
                                          f'{Color.GREEN}are not searched for configurations.{Color.NC}',
                                          MessageSeverity.Completion))

        # Completion
        self._messages.append(Message(f'{Color.ORANGE}{self._files_count}'
                                      f'{Color.BLUE} {self._file_type.title()} '
                                      f'{Color.GREEN}files have been converted to csv.{Color.NC}',
                                      MessageSeverity.Completion))
        return self._messages

    def _try_and_get_file_data(self, input_path, file_ext=None, excluded_file_extensions=()) -> list:
        # Validation
        _, ext = os.path.splitext(input_path)

        # Ext is not asked for or already blacklisted or a language: Ignore.
        if (file_ext and ext != file_ext) or ext in self._blacklist or ext in Language.ext2lang:
            return []

        # Add ext to blacklist if empty or to be excluded.
        if ext == EMPTY or ext in excluded_file_extensions:
            self._blacklist.add(ext)
            return []

        # Do not parse big files.
        size = Path(input_path).stat().st_size
        if size > MAX_CONFIG_FILE_SIZE_IN_BYTES:
            self._messages.append(Message(f'Big file ({round(size / 1000000, 1)} Mb) not processed: {input_path}',
                                          MessageSeverity.Warning))
            return []

        return self._get_file_data(input_path, session.input_dir)

    @staticmethod
    def _find_files(input_dir, ext):
        if not input_dir.startswith(ROOT_DIR):
            raise GeneralException('Directory name is not within the root directory.')
        for path, dirs, files in os.walk(os.path.abspath(input_dir)):
            for filename in files:
                if (not ext or filename.endswith(ext)) and not filename.startswith('.') \
                        and not any(i in path.lower() for i in ('test', 'mock')):
                    yield os.path.join(path, filename)

    def _get_file_data(self, input_path, input_dir) -> list:
        pass

    @staticmethod
    def get_output_file(file_type):
        return f'{session.log_dir}{CONFIGS_FOUND}_{file_type}{CSV_EXT}'

    def _write_lines(self, lines, data_path=None) -> bool:
        """
        Write lines to disk
        """
        if not lines:
            return True

        first = True
        with open(data_path, 'w') as csvFile:
            csv_writer = csv.writer(
                csvFile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            for row in lines:
                # ToDO: Header not dependent on db
                # if first:
                #     first = False
                #     header = Report.get_header(Report.ConfigFile)
                #     if len(header) != len(row):
                #         self._messages.append(Message(
                #             f'{__name__}: header has {len(header)} columns but rows have {len(row)}.',
                #             MessageSeverity.Error))
                #         return False
                #     # yaml:  [dir_name, file_name, row_no, level, item_key, item_value]
                #     # json:  ['FileName', 'Type', 'Name', 'Level', 'No', 'Key', 'Value']
                #     csv_writer.writerow(header)
                csv_writer.writerow(row)
        return True
