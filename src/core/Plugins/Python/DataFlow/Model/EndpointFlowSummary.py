# ---------------------------------------------------------------------------------------------------------------------
# ApiMethodFlowSummary.py
#
# Author      : Peter Heijligers
# Description : ParameterFlow Summary
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-02-11 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

class ApiMethodFlowSummary(object):
    def __init__(self, path, class_name, method_name, called_methods, returned_outputs):
        self._path = path
        self._class_name = class_name
        self._method_name = method_name
        self._called_methods = called_methods
        self._returned_outputs = returned_outputs

    """
    Getters
    """

    @property
    def path(self):
        return self._path

    @property
    def class_name(self):
        return self._class_name

    @property
    def method_name(self):
        return self._method_name

    @property
    def called_methods(self):
        return self._called_methods

    @property
    def returned_outputs(self):
        return self._returned_outputs
