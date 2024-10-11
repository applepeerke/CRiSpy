# ---------------------------------------------------------------------------------------------------------------------
# Endpoint.py
#
# Author      : Peter Heijligers
# Description : Endpoint (put/post/get) in a source file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-03-28 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.gl.Enums import MessageSeverity
from src.gl.Message import Message


class Endpoint(object):
    @property
    def ID(self):
        return self._ID

    @property
    def method_name(self):
        return self._method_name

    @property
    def route(self):
        return self._route

    @property
    def decorators(self):
        return self._decorators

    @property
    def authentication(self):
        return self._authentication

    @property
    def permission(self):
        return self._permission

    @property
    def authorization(self):
        return self._authorization

    @property
    def element(self):
        return self._element

    @property
    def vulnerable_field_names(self):
        return self._vulnerable_field_names

    @property
    def vulnerable_sanitizer(self):
        return self._vulnerable_sanitizer

    @property
    def vulnerable_usage(self):
        return self._vulnerable_usage

    @property
    def vulnerable(self):
        return self._vulnerable

    @property
    def input_sanitizers(self):
        return self._input_sanitizers

    @property
    def validation_items(self):
        return self._validation_items

    @property
    def output_sanitizer(self):
        return self._output_sanitizer

    @property
    def parameter_flows(self):
        return self._parameter_flows

    @property
    def called_methods(self):
        return self._called_methods

    @property
    def returned_outputs(self):
        return self._returned_outputs

    @property
    def messages(self):
        return self._messages

    # Setters
    @vulnerable.setter
    def vulnerable(self, value):
        self._vulnerable = value

    @vulnerable_field_names.setter
    def vulnerable_field_names(self, value):
        self._vulnerable_field_names = value
        if value:
            self._vulnerable = True

    @vulnerable_sanitizer.setter
    def vulnerable_sanitizer(self, value):
        self._vulnerable_sanitizer = value

    @vulnerable_usage.setter
    def vulnerable_usage(self, value):
        self._vulnerable_usage = value

    @input_sanitizers.setter
    def input_sanitizers(self, value):
        self._input_sanitizers = value

    @validation_items.setter
    def validation_items(self, value):
        self._validation_items = value

    @parameter_flows.setter
    def parameter_flows(self, value):
        self._parameter_flows = value
        [self._called_methods.add(m) for flow in value for m in flow.called_methods]
        [self._returned_outputs.add(r) for flow in value for r in flow.returned_outputs]
        if not self._vulnerable:
            self._vulnerable = any(PF.vulnerable for PF in self._parameter_flows)

    def __init__(self, element: Element, method_name=None, route=None, decorators=None, authentication=None,
                 permission=None, authorization=None, input_sanitizers=None, output_sanitizer=None, vulnerable=False):
        self._ID = f'{element.path}:{element.line_no}' if element else None  # required

        self._element = element
        self._route = route
        self._method_name = method_name
        self._decorators = decorators
        self._authentication = authentication
        self._permission = permission
        self._authorization = authorization
        self._input_sanitizers = input_sanitizers
        self._output_sanitizer = output_sanitizer
        self._vulnerable = vulnerable
        self._vulnerable_usage = False
        self._vulnerable_field_names = set()
        self._vulnerable_sanitizer = False
        self._messages = []
        self._called_methods = set()
        self._returned_outputs = set()
        self._validation_items = {}
        # Setters
        self._parameter_flows = []

    def add_message(self, text, severity=MessageSeverity.Error):
        self._messages.append(Message(text, severity))
        if severity == MessageSeverity.Error:
            self._vulnerable = True
