# ---------------------------------------------------------------------------------------------------------------------
# DjangoEndpointManager.py
# Author      : Peter Heijligers
# Description : ApiMethodsManager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-01-22 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.Enums import FrameworkName
from src.core.Plugins.Enums import HttpMethods
from src.core.Plugins.Python.DataFlow.ClassManager import ClassManager
from src.core.Plugins.Python.Endpoints.EndpointManager import EndpointManager
from src.core.Plugins.Python.Frameworks.Django.Constants import *
from src.core.Plugins.Python.Frameworks.Django.DjangoManager import DjangoManager
from src.core.Plugins.Python.Frameworks.Django.DjangoModelManager import DjangoModelManager
from src.core.Plugins.Python.Frameworks.Django.DjangoSanitizerManager import DjangoSanitizerManager
from src.gl.Const import BLANK, EMPTY
from src.gl.Enums import Color, MessageSeverity

DjangoM = DjangoManager()
class_manager = ClassManager()


class DjangoEndpointManager(EndpointManager):

    def __init__(self, framework_name):
        super().__init__(framework_name)
        self._validator_field_names = DjangoM.validator_field_names

    def endpoint_analysis(self):
        framework = self._frameworks.get(FrameworkName.Django) \
                    or self._frameworks.get(FrameworkName.Rest)
        # a. Scan on api_method names, input_names
        DjangoM.is_framework(self._session, framework.scanner)
        # b. Get fields
        # Preparation
        # - Create class-super dict
        if not class_manager.class_supers_dict:
            class_manager.scan_dir(self._session.input_dir)

        # - Find sanitized (validated) fields (e.g. " def validate_myField(...)"
        DjangoM.find_field_validators()

        # - Retrieve all fields (models and serializers)
        self._add_fields(DjangoModelManager(framework))

        # Get the endpoints
        self._get_endpoints(DjangoM, class_vulnerability_dict=None)

    def _add_sanitizer_fields(self, model_manager):
        SanM = DjangoSanitizerManager()  # Django/Rest Serializer fields
        SanM.sane_model_charfield_names = model_manager.get_sane_fields()
        SanM.find_fields(self._frameworks.get(self._framework_name).scanner)
        self._sanitizer_manager = SanM
        self._sanitizer_fields = SanM.fields
        self._add_messages(self._sanitizer_manager.messages)

    def _add_validation_items(self, line, endpoint: Endpoint) -> Endpoint:
        """
        Add lines to the endpoint containing ".is_valid()", ".validated_data" or ".data".
        """
        for i in VALIDATION_ITEMS:
            dot_or_empty = EMPTY if i == SUPER else '.'
            if f'{dot_or_empty}{i}' in line:  # E.g. mySerializer.validated_data
                # If serializer name = a method parameter like 'request', this is ok.
                if i == DATA and ('return' in line or self._get_serializer_name(line, i) in endpoint.element.line):
                    continue  # E.g. "return Response(myOutputSerializer.data)" is OK
                # item | line
                if endpoint.validation_items.get(i):
                    endpoint.validation_items[i].append(line)
                else:
                    endpoint.validation_items[i] = [line]
        return endpoint

    @staticmethod
    def _get_serializer_name(line, i) -> str:
        p = line.find(f'.{i}')
        s1 = line.rfind(BLANK, 0, p)
        s2 = line.rfind('=', 0, p)
        s = s2 if s2 > -1 else s1
        return line[s + 1:p]

    def _evaluate_endpoint_validation(self, endpoint: Endpoint) -> Endpoint:
        """
        Set Endpoint.vulnerable_usage.
        This is a warning only, else Endpoint.vulnerable is set; then all the connected fields are evaluated as
        vulnerable in the MIFV overview.
        """
        # Marshmallow has Schema, not Serializer sanitizing. So no need to look for "is_valid()" there.
        if self._has_marshmallow:
            return endpoint

        E = endpoint.element

        # a. Get is assumed sane.
        if endpoint.method_name == HttpMethods.Get:
            endpoint.add_message(
                f'{Color.GREEN}Input validation not investigated.{Color.NC} Get method is assumed sane.',
                severity=MessageSeverity.Info)
            return endpoint

        # b. Is validation delegated to super? Assume sane.
        #    E.g. return super().get(request)
        if endpoint.input_sanitizers and any(
                line.find(f'.{E.method_name}(') != -1 for line in endpoint.validation_items.get(SUPER, [])):
            for input_sanitizer in endpoint.input_sanitizers:
                endpoint.add_message(
                    f'{Color.GREEN}Delegated input validation{Color.NC}. '
                    f"Serializer '{input_sanitizer}.{IS_VALID}' is probably used in called super class.",
                    severity=MessageSeverity.Info)
            return endpoint

        # c. is_valid() is used in a called method name: Assume sane.
        for k, E in self._sanitizer_manager.sane_methods.items():
            for m in endpoint.called_methods:
                if k.endswith(f'|{m}'):
                    endpoint.add_message(
                        f"{Color.GREEN}Delegated input validation{Color.NC}. Serializer '.{IS_VALID}' "
                        f"is used in called method '{m}'.", severity=MessageSeverity.Info)
                    return endpoint

        # d. is_valid() is not used: vulnerable.
        warning = MessageSeverity.Warning
        if IS_VALID not in endpoint.validation_items:
            endpoint.add_message(
                f"{Color.ORANGE}Bypassing input validation{Color.NC}. Serializer '.{IS_VALID}' "
                f'is not used in this method.', severity=warning)
            endpoint.vulnerable_usage = True
            return endpoint

        # e. is_valid() is used without raising an error: vulnerable.
        if any(line.find('raise') == -1 for line in endpoint.validation_items.get(IS_VALID, [])):
            if VALIDATED_DATA not in endpoint.validation_items:
                endpoint.vulnerable_usage = True
                if DATA in endpoint.validation_items:
                    endpoint.add_message(
                        f"Bypassing input validation. Serializer '.{DATA}' is used instead of '{VALIDATED_DATA}'.",
                        severity=warning)
                else:
                    endpoint.add_message(
                        f"Bypassing input validation. Serializer '.is_valid()' is used without raising an error.",
                        severity=warning)
        return endpoint
