# ---------------------------------------------------------------------------------------------------------------------
# PluginManager_K8s.py
#
# Author      : Peter Heijligers
# Description : Java
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-09-16 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import FrameworkName, SecurityTopic
from src.core.Plugins.Const import IMPLEMENTED
from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.gl.Enums import Color

COLOURED_NOT = f'{Color.RED}NOT{Color.NC} '


class PlugInManager_CSharp(FrameworkPluginBase):

    def __init__(self, scanner):
        super().__init__(scanner)
        self._framework_name = FrameworkName.NET
        # self._endpoint_manager = EndpointManagerCSharp( self._framework_name, self._scanner)
        self._config_items = {}
        self._summary_dict = {}

    def run(self, frameworks=None, method_code=None):
        """ method_code is for unit test only """
        super().run(frameworks, method_code)
        # self._summary()

    def authentication(self):
        imports = ['AspNetCore.Components.WebAssembly.Authentication',
                   'AspNetCore.Authentication.Negotiate']  # ASP.NET
        self._add_topic(SecurityTopic.Authentication, imports)

    def authorization(self):
        imports = ['.AddRoles']  # ASP.NET
        self._add_topic(SecurityTopic.Authorization, imports)

    def endpoint_analysis(self):
        imports = ['@page']  # ASP.NET razor
        self._add_topic(SecurityTopic.Endpoint_analysis, imports)

    def _add_topic(self, topic, imports):
        if not self._frameworks.get(self._framework_name):
            return
        self._topic = topic
        self._topic_imports = set()
        [self._scan_for_imports(i) for i in imports]
        self._topic_message()
        # Output
        self._plugin_log_result(self._topic)
