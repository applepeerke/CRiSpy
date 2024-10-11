# ---------------------------------------------------------------------------------------------------------------------
# ParameterFlow.py
#
# Author      : Peter Heijligers
# Description : Parameter flow
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-06-15 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import FrameworkName
from src.core.DataLayer.Framework import DB_METHODS
from src.core.Plugins.Python.DataFlow.Model import MethodSignature, DataFlowPython
from src.core.Plugins.Const import OUTPUT, TYPE_CLASS, PARAMETER, TYPE_METHOD
from src.db.BusinessLayer.XRef.XRef_IO import XRef_IO
from src.db.BusinessLayer.XRef.XRef_MethodCall_manager import XRef_MethodCall_manager
from src.gl.Const import UNKNOWN


class ParameterFlow(object):
    def __init__(self, input_parameter,
                 method_signature: MethodSignature = None,
                 data_flows: [DataFlowPython] = None,
                 session=None,
                 framework=None):
        self._input_parameter = input_parameter
        self._method_signature = method_signature
        self._data_flows = data_flows
        self._session = session
        self._framework = framework if framework in DB_METHODS else FrameworkName.Unknown

        if session and session.db:
            self._has_db = True
            self._XR_MC = XRef_MethodCall_manager(session.db)
            self._XR_IO = XRef_IO(session.db)
        else:
            self._has_db = False

        self._called_methods, self._returned_outputs = [], []
        self._db_mutation = False
        self._parameter_used = False
        self._error_message = None
        self._vulnerable = any(df.vulnerable for df in data_flows) if data_flows else False
        self._calculate_flow_result()

    """
    Getters
    """

    @property
    def input_parameter(self):
        return self._input_parameter

    @property
    def method_signature(self):
        return self._method_signature

    @property
    def data_flows(self):
        return self._data_flows

    @property
    def called_methods(self):
        return self._called_methods

    @property
    def returned_outputs(self):
        return self._returned_outputs

    @property
    def db_mutation(self):
        return self._db_mutation

    @property
    def parameter_used(self):
        return self._parameter_used

    @property
    def error_message(self):
        return self._error_message

    @property
    def vulnerable(self):
        return self._vulnerable

    """
    Setters
    """

    @input_parameter.setter
    def input_parameter(self, value):
        self._input_parameter = value

    @method_signature.setter
    def method_signature(self, value):
        self._method_signature = value

    @data_flows.setter
    def data_flows(self, value):
        self._data_flows = value

    @called_methods.setter
    def called_methods(self, value):
        self._called_methods = value

    @returned_outputs.setter
    def returned_outputs(self, value):
        self._returned_outputs = value

    @parameter_used.setter
    def parameter_used(self, value):
        self._parameter_used = value

    @error_message.setter
    def error_message(self, value):
        self._error_message = value

    @vulnerable.setter
    def vulnerable(self, value):
        self._vulnerable = value

    # Transform parameter data-flow(s) to flow-result
    def _calculate_flow_result(self):
        self._called_methods = set()
        self._returned_outputs = set()
        if not self._data_flows:
            return

        for DF in self._data_flows:
            first = True
            for E in DF.elements:
                if first and E.value != self.input_parameter:
                    self._error_message = \
                        f"First element '{E.value}' must be equal to input parameter '{self._input_parameter}'"
                    return
                first = False
                if E.flow_type == TYPE_METHOD:
                    self._called_methods.add(E.value)
                    if self._get_db_mutation(E):
                        self._db_mutation = True
                if E.flow_mode == OUTPUT:
                    if E.flow_type in [TYPE_CLASS, PARAMETER, UNKNOWN]:
                        self._returned_outputs.add(E.value)

        # Parameter may not be used at all.
        self._parameter_used = False
        for DF in self._data_flows:
            if len(DF.elements) > 1:  # 1st element is parameter itself
                self._parameter_used = True

    def _get_db_mutation(self, E) -> bool:
        if not self._has_db or self._framework not in DB_METHODS:
            return False

        ns, module_name = E.get_ns_and_module_from_path(self._method_signature.path, self._session.input_dir)
        class_name = E.parent_value if E.parent_value else self._method_signature.class_name
        caller_method_id = self._XR_IO.get_ME_id_from_names(ns, module_name, class_name, E.value)
        if caller_method_id > -1:
            for name in DB_METHODS[self._framework]:
                if self._XR_MC.is_name_called_from(name, caller_method_id):
                    return True
        return False
