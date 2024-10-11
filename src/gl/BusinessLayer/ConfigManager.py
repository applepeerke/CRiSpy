# ---------------------------------------------------------------------------------------------------------------------
# ConfigManager.py
#
# Author      : Peter Heijligers
# Description : Return the configuration (app.config) in a dictionary.
# If app.config does not exist, it is created with default properties.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-23 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import json
import os
from typing import Optional

from fastapi import HTTPException
from starlette import status

from src.core.Functions.Functions import get_src_root_dir
from src.gl.BusinessLayer.Config_constants import *
from src.gl.ConfigItem import ConfigItem
from src.gl.Const import EMPTY, APP_NAME
from src.gl.Enums import LogLevel, LogType, ConfigType, ExecTypeEnum, ApplicationTypeEnum
from src.gl.Functions import stringed_list_to_list
from src.gl.GeneralException import GeneralException
from src.gl.Validate import normalize_dir, isBool, isInt, toBool, toFloat

configDef = {
    CF_SETTINGS_PATH: ConfigItem(
        'Settings folder', EMPTY, ConfigType.Path),
    CF_APPLICATION_TYPE: ConfigItem('Application type', ApplicationTypeEnum.Any.value, ConfigType.String),
    CF_COMPANY_NAME: ConfigItem('Company name', EMPTY, ConfigType.String),
    CF_INPUT_DIR: ConfigItem('Input directory', EMPTY, ConfigType.Dir),
    CF_PROJECT_NAME: ConfigItem('Project name', EMPTY, ConfigType.String),
    CF_CALCULATED_PROJECT_NAME: ConfigItem('Calculated project name', EMPTY, ConfigType.String),
    CF_CALCULATED_PROJECT_VALUE: ConfigItem('Calculated project value', EMPTY, ConfigType.String),
    CF_SPECIFIED_EXCLUDED_DIR_NAMES:
        ConfigItem('Excluded directories (comma separated, *)', [], ConfigType.List),
    CF_SPECIFIED_EXCLUDED_FILE_NAMES:
        ConfigItem('Excluded file names (comma separated, *)', [], ConfigType.List),
    CF_SPECIFIED_SANE_IF_PATTERN_IN:
        ConfigItem('Sane if pattern in verb (comma separated)', [], ConfigType.List),

    # Parameters
    CF_EXEC_TYPE: ConfigItem('Execution type', ExecTypeEnum.Both.value, ConfigType.String),
    CF_OUTPUT_DIR: ConfigItem('Output directory', EMPTY, ConfigType.Dir),
    CF_DATA_DIR: ConfigItem('Data directory', EMPTY, ConfigType.Dir),
    CF_CUSTOM_SEARCH_PATTERN: ConfigItem('Custom search pattern', EMPTY, ConfigType.String),
    CF_VERBOSE: ConfigItem('Verbose logging', False, ConfigType.Bool),
    CF_FILTER_FINDINGS: ConfigItem('Filter findings', True, ConfigType.Bool),
    CF_INCREMENTAL_SCAN: ConfigItem('Incremental scan', True, ConfigType.Bool),
    CF_QUICK_SCAN: ConfigItem('Quick scan', False, ConfigType.Bool),
    CF_SYNC_CVE: ConfigItem('Synchronize CVE', False, ConfigType.Bool),
    CF_SHOW_RESULTS: ConfigItem(None, True, ConfigType.Bool),
    CF_LOG_TITLE: ConfigItem('Log title', EMPTY, ConfigType.String),
    CF_LOG_DIR: ConfigItem(None, EMPTY, ConfigType.Dir),
    CF_OUTPUT_TYPE: ConfigItem('Log type', LogType.Both.value, ConfigType.String),
    CF_LOG_LEVEL: ConfigItem(None, LogLevel.Info, ConfigType.String),
    CF_TIME_EXEC_LOG_THRESHOLD_MS: ConfigItem('Scan time message threshold (ms)', 200, ConfigType.Int),
    CF_TIME_EXEC_MAX_S: ConfigItem('Scan time max (s)', 60 * 60, ConfigType.Int),

    # DB
    CF_DB_ACTION: ConfigItem('Database action', EMPTY, ConfigType.String),
    CF_DB_REBUILD_PROJECT_NAME: ConfigItem('Rebuild project name', EMPTY, ConfigType.String),

    # Debug
    CF_DEBUG_PATH: ConfigItem('Debug file path', EMPTY, ConfigType.Path),
    CF_DEBUG_PATTERN_NAME: ConfigItem('Debug pattern name', EMPTY, ConfigType.String),

    # Hidden
    CF_APPLY_BUSINESS_RULES: ConfigItem(None, True, ConfigType.Bool),
    CF_CATEGORY_COMPANY: ConfigItem(None, EMPTY, ConfigType.String),
    CF_CLEANUP: ConfigItem(None, True, ConfigType.Bool),
    CF_FILE_TYPES_INCLUDED: ConfigItem(None, [], ConfigType.List),
    CF_FILE_TYPES_EXCLUDED: ConfigItem(None, [], ConfigType.List),
    CF_PATH_PARTS_EXCLUDED: ConfigItem(None, [], ConfigType.List),
    CF_NIST_CVE_SYNC_LAST_DATE: ConfigItem(None, [], ConfigType.List),
}

config_desc_dict = {
    CF_SETTINGS_PATH: 'Settings pad',
    CF_APPLICATION_TYPE: 'Application type',
    CF_INPUT_DIR: 'Input directory',
    CF_COMPANY_NAME: 'Company name',
    CF_PROJECT_NAME: 'Project name',
    CF_CALCULATED_PROJECT_NAME: 'Calculated project name',
    CF_CALCULATED_PROJECT_VALUE: 'Calculated project value',
    CF_SPECIFIED_EXCLUDED_DIR_NAMES: 'Excluded directories (comma separated, *)',
    CF_SPECIFIED_EXCLUDED_FILE_NAMES: 'Excluded file names (comma separated, *)',
    CF_SPECIFIED_SANE_IF_PATTERN_IN: 'Sane if pattern in verb (comma separated)',
    # Params
    CF_OUTPUT_DIR: 'Output directory',
    CF_DATA_DIR: 'Data directory',
    CF_CUSTOM_SEARCH_PATTERN: 'Custom search pattern',
    CF_VERBOSE: 'Verbose logging',
    CF_FILTER_FINDINGS: 'Filter findings',
    CF_INCREMENTAL_SCAN: 'Incremental scan',
    CF_QUICK_SCAN: 'Quick scan',
    CF_SYNC_CVE: 'Synchronize CVE',
    CF_LOG_TITLE: 'Log title',
    CF_OUTPUT_TYPE: 'Log type',
    CF_EXEC_TYPE: 'Execution type',
    CF_TIME_EXEC_LOG_THRESHOLD_MS: 'Execution time message threshold (ms)',
    CF_TIME_EXEC_MAX_S: 'Scan time max (s)',
    # DB actions
    CF_DB_ACTION: 'Database action',
    CF_DB_REBUILD_PROJECT_NAME: 'Rebuild project name',
    # Debug
    CF_DEBUG_PATH: 'Debug file path',
    CF_DEBUG_PATTERN_NAME: 'Debug pattern name',
    # Hidden
    CF_NIST_CVE_SYNC_LAST_DATE: 'Last date of NIST CVE synchronisation '
}


def get_label(key) -> str:
    if key not in configDef:
        return key
    return configDef[key].label


def get_desc(key) -> str:
    if key not in config_desc_dict:
        return get_label(key)
    return config_desc_dict[key]


class ConfigManager:
    """ ConfigManager """

    class ConfigManagerInstance(object):

        @property
        def config_dict(self):
            return self._config_dict

        @config_dict.setter
        def config_dict(self, value):
            self._config_dict = value

        def __init__(self,
                     log_level=LogLevel.Info,
                     log_type=LogType.Both,
                     category_company=None,
                     project=None
                     ):
            self.logLevel = log_level
            self.logType = log_type
            self.categoryCompany = category_company
            self.project = project
            self._config_dict = {k: I.value for k, I in configDef.items()}
            self._root_dir = get_src_root_dir()

        def start_config(self):
            path = str(self.get_path())
            if not path:
                raise GeneralException(f"Configuration could not be initialized. Invalid path '{path}'")
            self.set_config_item(CF_SETTINGS_PATH, path)
            if not os.path.exists(path):
                self.write_config()
            # Read and verify config on disk
            self._config_dict = self._verify_config(path)

        def write_config(self):
            # First validate config in memory
            self._verify_config_content(self._config_dict)

            # Write to disk
            path = self.get_path()
            if os.path.isfile(path):
                os.remove(path)
            with open(path, "w") as f:
                json.dump(self._config_dict, f, indent=4)
                f.flush()

        @staticmethod
        def _fatal_error(message):
            """ Starting the configuration is the first step in the app. If this fails, show what happened. """
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)

        def _verify_config(self, path) -> dict:
            if not os.path.exists(path):
                self._fatal_error(f"Configuration does not exist in '{path}'")

            try:
                with open(path, "rb") as f:
                    d = json.load(f)
            except Exception as e:
                error_text = f'Configuration can not be loaded: {e}'
                self._fatal_error(error_text)

            # Verify all keys are in config (NB: temporary cache items in mem do not have to be on disk)
            not_in_config = {k for k in d if k not in configDef}
            if not_in_config:
                error_text = (f"Configuration verification has failed. Path is '{path}'\n "
                              f'Unsupported items: {not_in_config}')
                self._fatal_error(error_text)
            self._verify_config_content(d)
            return d

        def _verify_config_content(self, config: dict):
            """ After read and before write .json configuration. """
            # Verify configuration in memory. Check the types.
            [self._is_valid_type(k, v, configDef[k].validate_type) for k, v in config.items()]

        def _is_valid_type(self, key, value, validate_type) -> bool:
            if value is None:
                return True
            if validate_type == ConfigType.String:
                if not isinstance(value, str):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Int:
                if not isinstance(value, int):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.List:
                if not isinstance(value, list):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Bool:
                if not isBool(value):  # String representation in .json
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Float:
                if not isinstance(value, float):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Dir:
                if not isinstance(value, str) or (value and not normalize_dir(value)):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Path:
                if not isinstance(value, str or (value and not os.path.isfile(value))):
                    self._raise_invalid_type(key, validate_type)
            else:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f'Unsupported type {validate_type}.')
            return True

        def _raise_invalid_type(self, key, type):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f'Config item {get_label(key)} is not a {type}.')

        def get_config_item(self, key) -> Optional[str]:
            if key not in self._config_dict:
                return None
            return self._config_dict.get(key)

        def set_config_item(self, key, value):
            """ From OpenApi docs we get a string representation. """
            if key not in configDef:
                return
            validate_type = configDef[key].validate_type
            self._config_dict[key] = self._string_to_type(key, value, validate_type)

        def _string_to_type(self, key, value, validate_type: ConfigType):
            if validate_type == ConfigType.String:
                if not isinstance(value, str):
                    self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Int:
                if not isInt(value):
                    self._raise_invalid_type(key, validate_type)
                value = int(value)
            elif validate_type == ConfigType.List:
                if not isinstance(value, list):
                    value = stringed_list_to_list(value)
                    if not isinstance(value, list):
                        self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Bool:
                if not isinstance(value, bool):
                    value = toBool(value)
                    if not isinstance(value, bool):
                        self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Float:
                if not isinstance(value, float):
                    value = toFloat(value)
                    if not isinstance(value, float):
                        self._raise_invalid_type(key, validate_type)
            elif validate_type == ConfigType.Dir:
                if not isinstance(value, str):
                    value = normalize_dir(value)
            elif validate_type == ConfigType.Path:
                if not isinstance(value, str):
                    self._raise_invalid_type(key, validate_type)
            else:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f'Unsupported type {validate_type}.')
            return value

        @staticmethod
        def get_path() -> str:
            return f'{get_src_root_dir()}.{APP_NAME.lower()}.json'

    # storage for the instance reference
    __instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if ConfigManager.__instance is None:
            # Create and remember instance
            ConfigManager.__instance = ConfigManager.ConfigManagerInstance()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton__instance'] = ConfigManager.__instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self.__instance, attr, value)
