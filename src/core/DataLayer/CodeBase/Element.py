# ---------------------------------------------------------------------------------------------------------------------
# Element.py
#
# Author      : Peter Heijligers
# Description : Element in a source file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-08-01 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.Functions.Functions import slash
from src.core.Plugins.Const import TYPE_METHOD, TYPE_CLASS
from src.gl.Const import EMPTY
from src.gl.Functions import path_leaf


class Element(object):
    def __init__(self, path=None, line_no=None, pos: int = 0, name=None, type=None, line=None,
                 method_name=None, class_name=None, input_dir=None,
                 value=None, flow_type=None, data_type=None):
        # Code base attributes
        self._path = path
        self._line_no = line_no
        self._pos = pos
        self._name = name
        self._type = type

        # Flow attributes
        self._value = value
        self._flow_type = flow_type
        self._data_type = data_type

        # logical (almost redundant)
        self._method_name = method_name
        self._class_name = class_name
        self._input_dir = input_dir

        # Other
        self._line = line
        self._module_name = EMPTY
        self._namespace = EMPTY
        self._method_id = 0
        self._flow_mode = None
        self._parent_value = None

        # Derived
        self._namespace, self._module_name = self.get_ns_and_module_from_path(self._path, self._input_dir)

        if not name and not type:
            self._type = TYPE_METHOD if method_name else TYPE_CLASS
            self._name = method_name if method_name else class_name

    @property
    def path(self):
        return self._path

    @property
    def line_no(self):
        return self._line_no

    @property
    def pos(self):
        return self._pos

    @property
    def name(self):
        return self._name

    @property
    def type(self):
        return self._type

    @property
    def line(self):
        return self._line

    @property
    def namespace(self):
        return self._namespace

    @property
    def module_name(self):
        return self._module_name

    @property
    def class_name(self):
        return self._class_name

    @property
    def method_name(self):
        return self._method_name

    @property
    def value(self):
        return self._value

    @property
    def parent_value(self):
        return self._parent_value

    @property
    def flow_type(self):
        return self._flow_type

    @property
    def data_type(self):
        return self._data_type

    @property
    def flow_mode(self):
        return self._flow_mode

    @property
    def method_id(self):
        return self._method_id

    # Setters
    # -------
    @line_no.setter
    def line_no(self, value):
        self._line_no = value

    @pos.setter
    def pos(self, value):
        self._pos = value

    @line.setter
    def line(self, value):
        self._line = value

    @parent_value.setter
    def parent_value(self, value):
        self._parent_value = value

    @name.setter
    def name(self, value):
        self._name = value

    @value.setter
    def value(self, value):
        self._value = value

    @flow_type.setter
    def flow_type(self, value):
        self._flow_type = value

    @data_type.setter
    def data_type(self, value):
        self._data_type = value

    @flow_mode.setter
    def flow_mode(self, value):
        self._flow_mode = value

    @module_name.setter
    def module_name(self, value):
        self._module_name = value

    @namespace.setter
    def namespace(self, value):
        self._namespace = value

    @method_id.setter
    def method_id(self, value):
        self._method_id = value

    @staticmethod
    def get_ns_and_module_from_path(path, input_dir=None) -> (str, str):
        ns, module_name = EMPTY, EMPTY
        if path:
            ns, module_name = path_leaf( path )
            ns = f'{ns}{slash()}'
        if input_dir and ns:
            ns = ns.replace( input_dir, EMPTY ) if ns != input_dir else '.'
        return ns, module_name
