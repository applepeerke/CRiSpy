# ---------------------------------------------------------------------------------------------------------------------
# MethodSignature.py
#
# Author      : Peter Heijligers
# Description : Method signature
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-06-19 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
# method id dict
METHOD_PATH = 'path'
METHOD_NAME = 'method_name'
METHOD_CLASS_NAME = 'class_name'
METHOD_line_no_start = 'line_no_start'
METHOD_PARMS = 'parameters'


class MethodSignature(object):
    def __init__(self, path=None, class_name=None, method_name=None, line_no_start=None, parameters=None):
        self._path = path
        self._line_no_start = line_no_start
        self._method_name = method_name
        self._class_name = class_name
        self._parameters = parameters

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
    def line_no_start(self):
        return self._line_no_start

    @property
    def parameters(self):
        return self._parameters

    @path.setter
    def path(self, value):
        self._path = value

    @class_name.setter
    def class_name(self, value):
        self._class_name = value

    @method_name.setter
    def method_name(self, value):
        self._method_name = value

    @line_no_start.setter
    def line_no_start(self, value):
        self._line_no_start = value

    @parameters.setter
    def parameters(self, value):
        self._parameters = value
