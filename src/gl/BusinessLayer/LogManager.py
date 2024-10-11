# ---------------------------------------------------------------------------------------------------------------------
# Singleton.py
#
# Author      : Peter Heijligers
# Description : Log a line
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import os
import platform

from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Enums import LogLevel, LogType, Color, ColorWin, MessageSeverity as Sev

STRIPE = "----------------------------------------------------------------------------------------------------------"
EMPTY = ''
BLANK = ' '


def indent(line, indentation=0) -> str:
    header = ''.join([BLANK for _ in range(indentation)]) if indentation > 0 else EMPTY
    return f'{header}{line}'


class Singleton:
    """ Singleton """

    class LogManager:
        """Implementation of Singleton interface """

        log_level_sev = {
            LogLevel.Info: Sev.Info,
            LogLevel.Warning: Sev.Warning,
            LogLevel.Error: Sev.Error,
            LogLevel.Verbose: 0,
        }

        @property
        def log_level(self):
            return self._log_level

        @property
        def log_type(self):
            return self._log_type

        @property
        def log_file_name(self):
            return self._log_file_name

        @property
        def log_path(self):
            return self._log_path

        @property
        def is_progress_started(self):
            return self._is_progress_started

        @log_level.setter
        def log_level(self, value):
            self._log_level = value

        @log_type.setter
        def log_type(self, value):
            self._log_type = value

        @log_file_name.setter
        def log_file_name(self, value):
            self._log_file_name = value

        @log_path.setter
        def log_path(self, value):
            self._log_path = value

        @is_progress_started.setter
        def is_progress_started(self, value):
            self._is_progress_started = value

        def __init__(self):
            """
            Constructor
            """
            self._log_file_name = EMPTY
            self._log_path = EMPTY
            self._log_level = LogLevel.Verbose
            self._log_type = EMPTY
            self._is_progress_started = False
            self._progress_ceiling = 0
            self._progress_count = 0

            self._previous_line = EMPTY
            self._previous_line_raw = EMPTY
            self._previous_lineNC = EMPTY
            self._previous_line2 = EMPTY

            if platform.system().lower() == 'linux' \
                    or platform.system().lower() == 'osx' \
                    or platform.system().lower() == 'darwin':
                self.WindowsPlatform = False
            else:
                self.WindowsPlatform = True
            self._noColor = self._get_noColorToken()

        def get_color(self, color_name):
            if color_name == 'RED':
                if self.WindowsPlatform:
                    return ColorWin.RED
                else:
                    return Color.RED
            if color_name == 'BLUE':
                if self.WindowsPlatform:
                    return ColorWin.BLUE
                else:
                    return Color.BLUE
            if color_name == 'GREEN':
                if self.WindowsPlatform:
                    return ColorWin.GREEN
                else:
                    return Color.GREEN
            if color_name == 'ORANGE':
                if self.WindowsPlatform:
                    return ColorWin.ORANGE
                else:
                    return Color.ORANGE
            else:
                return EMPTY

        def start_log(self, log_type=LogType.Both, level=LogLevel.Verbose):
            """
            For a simple and verbose start of the _log
            """
            self.log_level = level
            self.log_type = log_type
            session = Session()
            if self._log_type != LogType.Stdout:
                if not os.path.exists(session.log_dir):
                    os.makedirs(session.log_dir)
                dir_name = session.log_dir_name
                # If dirname contains timestamp, filename can be simple.
                self.log_file_name = 'Log.txt' if sum(1 for e in dir_name if e.isnumeric()) >= 14 \
                    else f'Log_{session.log_dir_name}.txt'
                self._log_path = f'{session.log_dir}{self.log_file_name}'

        def add_line(self, line, min_level=None, indentation=0):
            """
            Log a line
            a. Forced verbose
            b. severity value <= _log level value
            c. No severity and Verbose
            """
            if not self._toBeLogged(min_level, line):
                return

            line = indent(line, indentation)
            self._previous_line2 = line

            self.stop_progressbar()  # Stop progress bar (just in case)

            # Stdout
            if not self.log_type or self.log_type == LogType.Both or self.log_type == LogType.Stdout:
                print(line)
            # File: no colors.
            if self.log_type == LogType.Both or self.log_type == LogType.File:
                self._append_file(str(line))

        def add_coloured_line(self, line, color=None, new_line=True, min_level=None, indentation=0):
            """
            Log a coloured line
            """
            if not self._toBeLogged(min_level, line):
                return

            line = indent(line, indentation)
            self._previous_line2 = line

            lineNC = line

            if color:
                color = self.get_color(color)
                line = f'{color}{line}{self._noColor}' if self._validate_color_platform(color) else line

            # Hold output
            if not new_line:
                self._previous_lineNC = lineNC + BLANK
                if color:
                    self._previous_line = f'{color}{line}{self._noColor}{BLANK}'
                else:
                    self._previous_line = f'{line}{BLANK}'

            # Write output
            else:
                self.stop_progressbar()  # Stop progress bar (just in case)
                # Stdout: with color (on non-windows platform).
                if self.log_type == LogType.Both or self.log_type == LogType.Stdout:
                    print(self._previous_line + line)
                # File
                if self.log_type == LogType.Both or self.log_type == LogType.File:
                    self._append_file(f'{str(self._previous_lineNC)}{str(lineNC)}')

                # Initialize previous fields
                self._previous_line = EMPTY
                self._previous_lineNC = EMPTY

        def _toBeLogged(self, min_level=None, line=EMPTY) -> bool:
            if not line:
                return False
            if line == STRIPE and self._previous_line2 == STRIPE:
                return False

            if not min_level or self._log_level == LogLevel.Verbose:  # Log
                return True

            # Specified level (in line) more verbose than default _log level: _log=Yes.
            if min_level == LogLevel.Verbose and self._log_level in [LogLevel.Verbose, LogLevel.Info, LogLevel.Error]:
                return True
            elif min_level == LogLevel.Info and self._log_level == LogLevel.Error:
                return True
            elif min_level == LogLevel.Error and self._log_level == LogLevel.Error:
                return True
            else:
                return False

        def _append_file(self, line):
            # File: no colors.
            with open(self._log_path, 'a') as txtFile:
                txtFile.write(self._colorless(line) + '\n')

        @staticmethod
        def _colorless(line):
            s = 0
            while s > -1:
                s = line.find('\033[')
                if s == -1:
                    break
                e = line.find('m', s)
                if e == -1:
                    break
                line = line.replace(line[s:e + 1], '')
            return line

        def progress(self, line=EMPTY, new_line=False, color=EMPTY):
            """
            Progress bar. Not in Verbose!
            Typically 1st time "line" contains a string, next times a progress character like "."
            """
            if line == EMPTY:
                return

            color = self._validate_color_platform(color)
            if color:
                line = color + line + self._get_noColorToken()

            if self.is_progress_started and self.log_type in (LogType.Both, LogType.Stdout):
                print(line, end='', flush=True) if not new_line else print(line)

        def progress_increment(self):
            if self._progress_ceiling > 0:
                self._progress_count += 1
                if self._progress_count > (self._progress_ceiling / 10):
                    self._progress_count = 0
                    self.progress('.')

        def _validate_color_platform(self, color):
            if self.WindowsPlatform == 'Windows':
                # TODO: Get windows coloring right. For now, no color for Windows.
                color = None
            return color

        def _get_noColorToken(self):
            if self.WindowsPlatform == 'Windows':
                return ColorWin.NC
            else:
                return Color.NC

        def start_progressbar(self, line=EMPTY, color=EMPTY, ceiling=0, in_verbose_mode=False):
            # A progress bar may be unwanted when all kinds of other info is shown too.
            if not in_verbose_mode and self._log_level == LogLevel.Verbose:
                return
            self.is_progress_started = True
            self._progress_ceiling = ceiling
            self.progress(line, new_line=False, color=color)

        def stop_progressbar(self):
            if self.is_progress_started:
                print(EMPTY)
            self.is_progress_started = False

        @staticmethod
        def new_line(strict=False):
            if strict:
                print('\n')
            else:
                print(EMPTY)

        def stripe(self, color='GREEN'):
            if self._previous_line_raw == STRIPE:
                return
            else:
                self.add_coloured_line(STRIPE, color)

        def get_log(self) -> list:
            lines = []
            if self.log_path:
                with open(self.log_path, 'r') as txtFile:
                    lines = txtFile.readlines()
            return [line.rstrip('\n') for line in lines]

    # storage for the instance reference
    _instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if Singleton._instance is None:
            # Create and remember instance
            Singleton._instance = Singleton.LogManager()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton_instance'] = Singleton._instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self._instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self._instance, attr, value)
