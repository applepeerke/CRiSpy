# ---------------------------------------------------------------------------------------------------------------------
# SessionManager.py
#
# Author      : Peter Heijligers
# Description : Log a line
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import datetime

from root_functions import get_root_dir, get_src_root_dir
from src.gl.Const import MODULE_CORE, SRC, APP_NAME, RESULTS_DIR, BASE_OUTPUT_SUBDIR, TESTS
from src.gl.Validate import *


class Singleton:
    """ Singleton """

    class SessionManager:
        """Implementation of Singleton interface """

        @property
        def ok(self):
            return self._ok

        @property
        def unit_test(self):
            return self._unit_test

        @property
        def company_name(self):
            return self._company_name

        @property
        def base_dir(self):
            return self._src_dir

        @property
        def has_db(self):
            return self._has_db

        @property
        def db(self):
            return self._db

        @property
        def data_dir(self):
            return self._data_dir

        @property
        def db_name(self):
            return self._db_name

        @property
        def import_dir(self):
            return self._import_dir

        @property
        def output_dir(self):
            return self._output_dir

        @property
        def design_dir(self):
            return self._design_dir

        @property
        def backup_dir(self):
            return self._backup_dir

        @property
        def rebuild_dir(self):
            return self._rebuild_dir

        @property
        def log_dir(self):
            return self._log_dir

        @property
        def log_dir_name(self):
            return self._log_dir_name

        @property
        def custom_pattern(self):
            return self._custom_pattern

        @property
        def input_dir(self):
            return self._input_dir

        @property
        def plugins_dir(self):
            return self._plugins_dir

        @property
        def images_dir(self):
            return self._images_dir

        @property
        def debug_path(self):
            return self._debug_path

        @property
        def endpoints_path(self):
            return self._endpoints_path

        @property
        def debug_pattern_name(self):
            return self._debug_pattern_name

        @property
        def is_started(self):
            return self._is_started

        """
        Setters
        """

        @company_name.setter
        def company_name(self, value):
            self._company_name = value

        @data_dir.setter
        def data_dir(self, value):
            self._data_dir = value

        @db_name.setter
        def db_name(self, value):
            self._db_name = value

        @db.setter
        def db(self, value):
            self._db = value

        @custom_pattern.setter
        def custom_pattern(self, value):
            self._custom_pattern = value

        @input_dir.setter
        def input_dir(self, value):
            self._input_dir = value

        @debug_path.setter
        def debug_path(self, value):
            self._debug_path = value

        @endpoints_path.setter
        def endpoints_path(self, value):
            self._endpoints_path = value

        @debug_pattern_name.setter
        def debug_pattern_name(self, value):
            self._debug_pattern_name = value

        def __init__(self):
            """
            Constructor
            """
            self._ok = True
            self._company_name = EMPTY
            self._src_dir = EMPTY
            self._tests_dir = EMPTY
            self._output_dir = EMPTY
            self._has_db = False
            self._db_name = EMPTY
            self._data_dir = EMPTY
            self._db = None

            self._design_dir = EMPTY
            self._import_dir = EMPTY
            self._backup_dir = EMPTY
            self._rebuild_dir = EMPTY
            self._log_dir = EMPTY
            self._plugins_dir = EMPTY
            self._images_dir = EMPTY
            self._custom_pattern = EMPTY
            self._log_dir_name = EMPTY
            self._unit_test = False
            self._app_root_dir = EMPTY
            self._input_dir = EMPTY
            self._debug_path = EMPTY
            self._endpoints_path = EMPTY
            self._debug_pattern_name = EMPTY
            self._is_started = False
            try:
                from src.db.DataLayer.DBDriver.DBDriver import DBDriver
                self._has_db = True
            except ImportError or ModuleNotFoundError:
                self._has_db = False

        def set_paths(self, unit_test=False, module_name=MODULE_CORE, input_dir=None, data_dir=None, output_dir=None,
                      suffix=None, restart_session=False):
            self._unit_test = unit_test
            self._input_dir = input_dir
            self._data_dir = data_dir
            self._output_dir = output_dir

            # In Unittest in Core turn off DB.
            if unit_test and module_name == MODULE_CORE and not self._db:
                self._has_db = False

            # Session is considered started if the same log paths have already been set.
            if self._is_started and not restart_session and not unit_test and (
                    (not suffix and not self._log_dir_name
                     or (suffix and self._log_dir_name and self._log_dir_name.endswith(suffix)))):
                return

            # app_root_dir
            root_dir = get_root_dir()
            self._app_root_dir = get_src_root_dir()
            self._src_dir = normalize_dir(f'{self._app_root_dir}{SRC}')
            self._tests_dir = normalize_dir(f'{self._app_root_dir}{TESTS}')
            if not self._src_dir:
                return

            resources_dir = normalize_dir(f'{self._app_root_dir}resources')
            self._images_dir = normalize_dir(f'{resources_dir}images')
            self._import_dir = normalize_dir(f'{resources_dir}import')

            # Output and Data should normally be kept outside the program directory
            if not output_dir:
                self._output_dir = normalize_dir(f'{root_dir}Output', create=True)

            # Log dir
            log_subdir = RESULTS_DIR if not unit_test else f'{RESULTS_DIR}_UnitTest'
            log_dir_root = normalize_dir(f'{self._output_dir}{log_subdir}', create=True)
            log_dir_name = f"{BASE_OUTPUT_SUBDIR}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self._log_dir_name = f'{log_dir_name}_{suffix}' if suffix else log_dir_name
            self._log_dir = normalize_dir(f'{log_dir_root}{self._log_dir_name}')
            # Only create log directories with a suffix.
            if suffix or unit_test:
                self._log_dir = normalize_dir(f'{self._log_dir}', create=True)

            # CRiSp application
            self._plugins_dir = normalize_dir(f'{self._import_dir}PlugIns')
            self.set_design_dir(module_name)  # Module dependent unittest input

            if self._has_db:
                self._db_name = f'{APP_NAME}.db'
                self.set_data_dir(self._data_dir, unit_test, log_dir_root)

            self._is_started = True

        def set_data_dir(self, data_dir, unit_test=False, log_dir_root=EMPTY):
            if unit_test:
                self._data_dir = normalize_dir(f'{log_dir_root}Data', create=True)
                self._rebuild_dir = normalize_dir(f'{self._design_dir}Rebuild')
                self._backup_dir = normalize_dir(f'{self._data_dir}Backup', create=True)
            else:
                if data_dir:
                    self._data_dir = normalize_dir(data_dir, create=True)
                    if self._data_dir:
                        self._rebuild_dir = normalize_dir(f'{self._data_dir}Rebuild', create=True)
                        self._backup_dir = normalize_dir(f'{self._data_dir}Backup', create=True)

        def set_design_dir(self, module_name=MODULE_CORE):
            self._design_dir = self._import_dir if not self._unit_test \
                else normalize_dir(f'{self._tests_dir}{module_name}{slash()}UnitTest{slash()}Design')

    # ---------------------------------------------------------------------------------------------------------------------
    # Singleton logic
    # ---------------------------------------------------------------------------------------------------------------------

    # storage for the instance reference
    __instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if Singleton.__instance is None:
            # Create and remember instance
            Singleton.__instance = Singleton.SessionManager()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton__instance'] = Singleton.__instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self.__instance, attr, value)
