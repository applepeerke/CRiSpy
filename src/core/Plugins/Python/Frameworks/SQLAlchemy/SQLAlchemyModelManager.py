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
from src.core.Plugins.Python.Frameworks.SQLAlchemy.SQLAlchemyFieldManager import SQLAlchemyFieldManager


class SQLAlchemyModelManager(ModelManagerBase):

    def __init__(self, framework):
        super().__init__(framework)

    def _add_fields(self):
        """
        For 1 framework_name (Django, SQLAlchemy, MarshMallow, Pydantic), add the fields.
        The Framework already contains the initialized scan results.
        """
        super()._add_fields()
        self._field_manager = SQLAlchemyFieldManager(self._parser)
        self._find_fields()
