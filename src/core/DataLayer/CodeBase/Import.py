# ---------------------------------------------------------------------------------------------------------------------
# Import.py
#
# Author      : Peter Heijligers
# Description : Search pattern
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-06-27 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------


class Import(object):

    # Getters
    @property
    def class_name(self):
        return self._class_name

    @property
    def location(self):
        return self._location

    @property
    def local_class_name(self):
        return self._local_class_name

    # Setters
    @class_name.setter
    def class_name(self, val):
        self._class_name = val

    @location.setter
    def location(self, val):
        self._location = val

    @local_class_name.setter
    def local_class_name(self, val):
        self._local_class_name = val

    def __init__(self,
                 class_name=None,
                 location=None,
                 local_class_name=None):
        self._class_name = class_name
        self._location = location
        self._local_class_name = local_class_name
