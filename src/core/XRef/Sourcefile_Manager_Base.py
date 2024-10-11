# ---------------------------------------------------------------------------------------------------------------------
# Sourcefile_Manager_Python.py
#
# Author      : Peter Heijligers
# Description : Build a call x-ref from a source file.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import abc
from src.db.BusinessLayer.XRef.XRef_Module_manager import XRef_Module_manager
from src.db.BusinessLayer.XRef.XRef_MethodCall_manager import XRef_MethodCall_manager
from src.db.BusinessLayer.XRef.XRef_Method_manager import XRef_Method_manager
from src.db.BusinessLayer.XRef.XRef_Class_manager import XRef_Class_manager
from src.gl.Parse.Parser_Python import Parser_Python

EOF = 'b\'\''
CRLF = '\\r\\n'
IMPORT = 'import'
FROM = 'from'
DEF = 'def'
CLASS = 'class'
AS = 'as'
SRCFILE = '*Module'

METHODS_IGNORE = ['_init_']
CLASSES_IGNORE = ['object']

supported_file_types = ['.py']

parser = Parser_Python()

""" 
Precondition: pos always on 1st position of the item to be processed, or -1
"""


class Sourcefile_Manager_Base(metaclass=abc.ABCMeta):

    @property
    @abc.abstractmethod
    def error_message(self):
        pass

    @property
    @abc.abstractmethod
    def warning_messages(self):
        pass

    def __init__(self, db=None, store_external_library_calls=False):
        self._db = db
        self._module_name = None
        self._this_class_name = None
        self._current_class = None
        self._current_method = None
        self._this_ns = None
        self._current_class_types = None
        self._error_message = None
        self._warning_messages = []
        self._prefix = None
        self._local_class_names = {}

        self._module_manager = XRef_Module_manager(db) if db else None
        self._method_manager = XRef_Method_manager(db) if db else None
        self._class_manager = XRef_Class_manager(db) if db else None
        self._call_manager = XRef_MethodCall_manager(db) if db else None
        if self._call_manager:
            self._call_manager.store_external_library_calls = store_external_library_calls

    @abc.abstractmethod
    def parse_file(self, path, def_mode, base_dir):
        pass

    @abc.abstractmethod
    def _parse(self, path, def_mode=False):
        pass

    @abc.abstractmethod
    def _set_Import_def(self, item, def_mode=False):
        pass

    @abc.abstractmethod
    def _set_Module_def(self, def_mode=False):
        pass

    @abc.abstractmethod
    def _set_Class_def(self, def_mode=False):
        pass

    @abc.abstractmethod
    def _set_Method_def(self, def_mode=False):
        pass

    @abc.abstractmethod
    def _set_Method_call(self):
        pass

    def _get_class_name(self, dot) -> str:
        pass
