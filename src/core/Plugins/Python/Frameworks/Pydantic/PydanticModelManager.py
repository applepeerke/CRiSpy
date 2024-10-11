# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : ModelManager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-11-02 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.Plugins.Python.Endpoints.ModelManagerBase import ModelManagerBase
from src.core.Plugins.Python.Endpoints.SanitizerManagerPython import SanitizerManagerPython
from src.core.Plugins.Python.Frameworks.Pydantic.PydanticFieldManager import PydanticFieldManager
from src.core.Plugins.Python.Validators.ValidatorPydantic import ValidatorPydantic


class PydanticModelManager(ModelManagerBase, SanitizerManagerPython):

    def __init__(self, framework):
        super().__init__(framework)

    def _add_fields(self):
        """
        For 1 framework_name (Django, SQLAlchemy, MarshMallow, Pydantic), add the fields.
        The Framework already contains the initialized scan results.
        """
        super()._add_fields()
        self._field_manager = PydanticFieldManager(self._parser)
        self._validator_manager = ValidatorPydantic()
        self._find_fields()
        self.sanitize_fields_of_complex_types()
