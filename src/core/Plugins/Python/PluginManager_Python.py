# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_Python.py
#
# Author      : Peter Heijligers
# Description : Python plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-07 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from abc import ABC

from src.core.DataLayer.Enums import FrameworkName, SecurityTopic
from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.core.Plugins.Python.Frameworks.Django.AuthenticationManager import AuthenticationManager
from src.core.Plugins.Python.Frameworks.Django.DjangoEndpointManager import DjangoEndpointManager
from src.core.Plugins.Python.Frameworks.Django.DjangoManager import DjangoManager
from src.core.Plugins.Python.Frameworks.Django.SettingsAnalysis import SettingsAnalysis, PASSWORD_POLICIES, \
    SECURITY_MIDDLEWARE, SESSION_MANAGEMENT
from src.core.Plugins.Python.Frameworks.FastAPI.FastAPIEndpointManager import FastAPIEndpointManager
from src.core.Plugins.Python.Frameworks.Marshmallow.MarshmallowEndpointManager import MarshmallowEndpointManager
from src.core.Plugins.Python.Frameworks.Rest.RestManager import RestManager
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.LogManager import STRIPE
from src.gl.Const import EMPTY
from src.gl.Enums import Color, MessageSeverity
from src.gl.Message import Message

PGM = 'PluginManager_Python'

ConfigM = ConfigManager()
SettingsM = SettingsAnalysis()

DjangoM = DjangoManager()
RestM = RestManager()


class PlugInManager_Python(FrameworkPluginBase, ABC):

    @property
    def fields(self):  # UT only
        return self._fields

    def __init__(self, scanner):
        super().__init__(scanner)
        self._frameworks = {}

    """
    A. Configuration - Analyze settings.py
    """

    def configuration(self):
        # Settings
        self._framework_name = EMPTY
        framework = self._frameworks.get(FrameworkName.Django)
        if framework:
            self._framework_name = framework.name
            DjangoM.is_framework(self._session, framework.scanner)
            SettingsM.set_settings_paths(DjangoM)

            # Go!
            self._messages = [Message(f'{Color.GREEN}{STRIPE}{Color.NC}', MessageSeverity.Completion)]  # output
            SettingsM.settings_to_dict()
            self._messages.append(SettingsM.walk_settings_paths(PASSWORD_POLICIES))
            self._messages.append(SettingsM.walk_settings_paths(SECURITY_MIDDLEWARE))
            self._messages.append(SettingsM.walk_settings_paths(SESSION_MANAGEMENT))
            # if ConfigM.get_config_item( CF_COMPANY_NAME ) == 'KPN':
            #     self._messages.append( SettingsM.walk_settings_paths( WHITELIST_MIDDLEWARE ) )
            # In Django, COOKIE_SECURE is False by default.
            self._messages.extend(SettingsM.check_inline_settings(
                {'SESSION': 'cookie_secure',
                 'CSRF': 'cookie_secure',
                 'HSTS': 'hsts'}))

        self._plugin_log_result(SecurityTopic.Configuration)

    """
    B. Endpoint analysis - Analyze vulnerability of endpoints
    """

    def _endpoint_analysis(self, title=EMPTY):
        self._messages = []  # output
        self._title = title
        self._framework_names = []

        # Django and Rest: Django processing.
        framework = self._frameworks.get(FrameworkName.Django) \
                    or self._frameworks.get(FrameworkName.Rest)
        if framework:
            self._framework_names.append(framework.name)
            self._endpoint_manager = DjangoEndpointManager(framework.name)
            self._endpoint_analysis_framework()

        # FastApi
        framework = self._frameworks.get(FrameworkName.FastApi) \
                    or self._frameworks.get(FrameworkName.Pydantic)
        if framework:
            self._framework_names.append(framework.name)
            self._endpoint_manager = FastAPIEndpointManager(framework.name)
            self._endpoint_analysis_framework()

        # Marshmallow
        framework = self._frameworks.get(FrameworkName.Marshmallow)
        if framework:
            self._framework_names.append(framework.name)
            self._endpoint_manager = MarshmallowEndpointManager(framework.name)
            self._endpoint_analysis_framework()

    """
    C. Authentication - Analyze settings and endpoints (e.g. apiview in get/post/put)
    """

    def authentication(self):
        self._messages = []
        framework = None
        self._framework_name = EMPTY

        if self._frameworks.get(FrameworkName.Django):
            framework = self._frameworks.get(FrameworkName.Django)
        elif self._frameworks.get(FrameworkName.Rest):
            framework = self._frameworks.get(FrameworkName.Rest)
        elif self._frameworks.get(FrameworkName.FastApi):
            framework = self._frameworks.get(FrameworkName.FastApi)

        if framework:
            self._framework_name = framework.name
            authc = AuthenticationManager()
            if framework.name in (FrameworkName.Rest, FrameworkName.Django):
                RestM.is_framework(self._session, framework.scanner)  # Retrieve decorators
                authc.authentication_django(SettingsM, RestM)
            authc.authentication_endpoints(framework.name, self._endpoints, RestM.decorators)

            self._messages = authc.messages

        self._plugin_log_result(SecurityTopic.Authentication)
