# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_Python.py
#
# Author      : Peter Heijligers
# Description : Java versions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2023-03-13 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.Plugins.Versions.VersionsBase import VersionsBase
from src.utils.XmlPom2Dict import XmlPom2Dict


class Versions_java(VersionsBase):

    def __init__(self, scanner, cli_mode=False):
        super().__init__(scanner, cli_mode)

    def _add_versions(self, filename, path):
        parser = XmlPom2Dict()
        self._versions_by_path[path] = parser.get_versions(path)
