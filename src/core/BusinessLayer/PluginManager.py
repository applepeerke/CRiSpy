# ---------------------------------------------------------------------------------------------------------------------
# PluginManager.py
#
# Author      : Peter Heijligers
# Description : PluginManager.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-31 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.ExternalLinksManager import ExternalLinksManager
from src.core.BusinessLayer.Scanner import Scanner
from src.core.DataLayer.Enums import ColorText, FrameworkName
from src.core.Plugins.AWS.PluginManager_AWS import PlugInManager_AWS
from src.core.Plugins.CSharp.PluginManager_CSharp import PlugInManager_CSharp
from src.core.Plugins.ExternalLinks import ExternalLinks
from src.core.Plugins.JS.PluginManager_JS import PlugInManager_JS
from src.core.Plugins.Java.PluginManager_Java import PlugInManager_Java
from src.core.Plugins.K8s.PluginManager_K8s import PluginManager_K8s
from src.core.Plugins.Python.PluginManager_Python import PlugInManager_Python
from src.core.Plugins.Versions.Versions_java import Versions_java
from src.core.Plugins.Versions.Versions_python import Versions_python
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.Config_constants import CF_OUTPUT_DIR, CF_LOG_LEVEL, CF_SYNC_CVE
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import EMPTY
from src.gl.Enums import LogLevel, Language, ExecTypeEnum

log = Log()
CM = ConfigManager()
externalLinks = ExternalLinks()
DATAFLOW = 'DataFlow'


class PluginManager(object):
    def __init__(self, exec_type: ExecTypeEnum, LA_manager, frameworks: dict, scanner: Scanner, cli_mode=False):
        self._exec_type = exec_type
        self._LA_manager = LA_manager
        self._frameworks = frameworks
        self._scanner = scanner
        self._cli_mode = cli_mode

    def run(self):
        log.stripe()
        self._log('PlugIns', ColorText.Green, one_time_log_level=LogLevel.Verbose)  # Always display this

        self._external_links()
        self._configuration_plugins()
        self._language_plugins()
        self._versions_plugins()

    def _external_links(self):
        """
        Create Findings_internal.csv
        Findings.txt. files for internal use (e,g, External links) are parked in subfolder "Findings_internal".
        These are aggregated in the same way as in the parent folder.
        """
        session = Session()
        pm = ExternalLinksManager(session)

        # Extract external-links from findings
        if self._exec_type != ExecTypeEnum.DataFlow:
            self._get_external_links(pm.external_links())

    def _configuration_plugins(self):
        # K8s
        if FrameworkName.K8s in self._frameworks:
            PluginManager_K8s(self._scanner).run(self._frameworks)
        # AWS
        if FrameworkName.AWS in self._frameworks:
            PlugInManager_AWS(self._scanner).run(self._frameworks)

    def _language_plugins(self):
        # Python
        if Language.Python in self._LA_manager.language_names:
            PlugInManager_Python(self._scanner).run(self._frameworks)
        # JavaScript
        if Language.JavaScript in self._LA_manager.language_names:
            PlugInManager_JS(self._scanner).run(self._frameworks)
        # Java
        if Language.Java in self._LA_manager.language_names:
            PlugInManager_Java(self._scanner).run(self._frameworks)
        # C#
        if Language.CSharp in self._LA_manager.language_names:
            PlugInManager_CSharp(self._scanner).run(self._frameworks)

    def _versions_plugins(self):
        # Ignore version scanning if there is no CVE syncing (e.g. debug mode)
        if CM.get_config_item(CF_SYNC_CVE) is not True:
            return

        # Python
        if Language.Python in self._LA_manager.language_names:
            Versions_python(self._scanner, self._cli_mode).run('requirements.txt')
            Versions_python(self._scanner, self._cli_mode).run('poetry.lock')
        # Java
        if Language.Java in self._LA_manager.language_names:
            Versions_java(self._scanner, self._cli_mode).run('pom.xml')

    @staticmethod
    def _get_external_links(find_path=None):
        if find_path:
            external_links_path = CM.get_config_item(CF_OUTPUT_DIR)
            externalLinks.get_rows_with_external_links(find_path, external_links_path)

    def _log(self, line, color=EMPTY, new_line=True, one_time_log_level=None, error=False):
        # Set _log level
        if one_time_log_level:
            self._log_level = one_time_log_level
        # Log line
        log.add_coloured_line(line, color, new_line, self._log_level)
        # Reset _log level
        if one_time_log_level:
            self._log_level = CM.get_config_item(CF_LOG_LEVEL)
        # Remember last error
        if error:
            self._error_message = line
