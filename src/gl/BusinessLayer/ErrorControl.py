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

import traceback

from src.gl.GeneralException import GeneralException
from src.gl.BusinessLayer.LogManager import Singleton as Log

EMPTY = ''


class ErrorType(object):
    Int = 'INT'
    Text = 'TEXT'
    Blob = 'BLOB'
    Exception = 'Exception'
    SqlException = 'SqlException'
    Error = 'Error'
    Warning = 'Warning'
    Info = 'Info'
    Any = 'Any'
    Ok = 'OK'

    raise_types = (Exception, SqlException, Error)


class Singleton:
    """ Singleton """

    class ErrorControl:
        """Implementation of Singleton interface """

        def __init__(self):
            """
            Constructor
            """
            self._error_dict = {}
            self._last_error = EMPTY

        def add_line(self, error_type, line):
            """
            Log a line
            """
            # Can be unicode too..
            # assert isinstance(line, str), "line %s is not a string" % str(line)
            # assert isinstance(error_type, str), "error_type %e is not a string" % str(error_type)

            self._last_error = line
            self.save_error(error_type)

            # _log a line
            if Log() is None or not Log().log_file_name:
                print(line)
            else:
                Log().add_line(line)

            if error_type in ErrorType.raise_types:
                raise GeneralException(line)

        def log_exception(self, ex, ex_traceback=None):
            """
            Log an exception
            """
            if ex_traceback is None:
                ex_traceback = ex.__traceback__
            tb_lines = [line.rstrip('\n') for line in
                        traceback.format_exception(ex.__class__, ex, ex_traceback)]
            for line in tb_lines:
                self.add_line(ErrorType.Exception, line)

        def save_error(self, error_type):
            """
            Save error count per type
            """
            if error_type in self._error_dict:
                self._error_dict[error_type] += 1
            else:
                self._error_dict[error_type] = 1

        def yield_errors(self, error_type=ErrorType.Any):
            """
            Return error counts per type
            """
            if error_type == ErrorType.Any:
                return self._error_dict
            else:
                return self._error_dict[error_type]

        def yield_last_error(self, clear=True):
            last_error = self._last_error
            if clear:
                self._last_error = EMPTY
            return last_error

    # storage for the instance reference
    __instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if Singleton.__instance is None:
            # Create and remember instance
            Singleton.__instance = Singleton.ErrorControl()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton__instance'] = Singleton.__instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self.__instance, attr, value)
