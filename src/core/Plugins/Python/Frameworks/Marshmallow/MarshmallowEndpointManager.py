from src.core.DataLayer.Enums import FrameworkName
from src.core.Plugins.Python.Endpoints.EndpointManager import EndpointManager
from src.core.Plugins.Python.Endpoints.SanitizerManagerPython import SanitizerManagerPython
from src.core.Plugins.Python.Frameworks.Marshmallow.MarshmallowModelManager import MarshmallowModelManager


class MarshmallowEndpointManager(EndpointManager):

    def __init__(self, framework_name):
        super().__init__(framework_name)

    def endpoint_analysis(self):
        self._sanitizer_manager = SanitizerManagerPython()
        framework = self._frameworks[FrameworkName.Marshmallow]
        self._add_fields(MarshmallowModelManager(framework))
        # Marshmallow uses no serializers, only models (Schemas). So put the Schema fields in the sanitizer.
        self._sanitizer_manager.fields = self._fields
