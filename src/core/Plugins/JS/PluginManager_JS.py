# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_AWS.py
#
# Author      : Peter Heijligers
# Description : JavaScript plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-06-05 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from abc import ABC

from src.core.DataLayer.Enums import FrameworkName, SecurityTopic

from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.core.Plugins.JS.check_versions import get_vulnerable_versions
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Const import CSV_EXT
from src.gl.Enums import MessageSeverity
from src.gl.Functions import find_file, path_leaf
from src.gl.Message import Message
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.core.Functions.Functions import slash

PGM = 'PluginManager_JS'

slash = slash()


class PlugInManager_JS(FrameworkPluginBase, ABC):

    def __init__(self, scanner):
        super().__init__(scanner)
        self._framework_name = FrameworkName.JS

    def configuration(self):
        # one level up should contain package info.
        root_dir, _ = path_leaf(Session().input_dir)
        versions_path = find_file('package-lock.json', root_dir)
        if versions_path:
            messages = get_vulnerable_versions(versions_path, self._get_latest_safe_module_versions())
            self._messages = [Message(m, MessageSeverity.Error) for m in messages]
        self._plugin_log_result(SecurityTopic.Configuration)

    def authentication(self):
        self._plugin_log_result(SecurityTopic.Authentication)

    def _endpoint_analysis(self):
        pass

    def _endpoint_analysis_output(self):
        pass

    @staticmethod
    def _get_latest_safe_module_versions() -> list:
        if Session().plugins_dir:
            return CsvManager().get_rows(
                data_path=f'{Session().plugins_dir}JS{slash}Latest_safe_versions{CSV_EXT}')
