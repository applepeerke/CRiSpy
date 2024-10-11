# ---------------------------------------------------------------------------------------------------------------------
# YamlManager.py
#
# Author      : Peter Heijligers
# Description : Yaml specifics
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-07-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import ConfigFileType
from src.core.Plugins.AWS.Config.ConfigBaseManager import ConfigBaseManager
from src.core.Plugins.AWS.Constants import START_OF_ENDPOINTS, START_OF_MODELS, START_OF_ENDPOINT, START_OF_MODEL


class YamlManager(ConfigBaseManager):

    def __init__(self):
        super().__init__(ConfigFileType.Yaml)

    def endpoint_analysis(self):
        """
        Analyze .yaml that has been transformed to .csv.
        """
        # A. Endpoints
        input_fields = self._get_yaml_fields(START_OF_ENDPOINTS, START_OF_ENDPOINT)

        # B. Schema's
        model_fields = self._get_yaml_fields(START_OF_MODELS, START_OF_MODEL)

        # C. Merge
        self._merge_fields(input_fields, model_fields)

    def _get_yaml_fields(self, key_multiple, key_single):
        """ First try multiple, then single. """
        fields = self._get_fields(self._get_info_from_csv(find_key=key_multiple), used_for_input=True)
        if not fields:
            fields = self._get_fields(self._get_info_from_csv(find_key=key_single), used_for_input=True)
        return fields
