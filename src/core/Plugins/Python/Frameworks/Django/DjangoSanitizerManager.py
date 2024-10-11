# ---------------------------------------------------------------------------------------------------------------------
# Django_source_analyzer.py
#
# Author      : Peter Heijligers
# Description : Python validation vulnerabilities
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-01-22 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.CodeBase.Sanitizer import Sanitizer
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import CLASS, DEF, VARIABLE, SANITIZED_BY_MODEL, \
    SANITIZED_AT_FIELD_LEVEL, SANITIZED_AT_OBJECT_LEVEL, SANITIZED_IN_META, METHOD
from src.core.Plugins.Enums import ContainerType, HttpMethods
from src.core.Plugins.Python.Endpoints.SanitizerManagerPython import SanitizerManagerPython
from src.core.Plugins.Python.Frameworks.Django.DjangoFieldManager import DjangoFieldManager
from src.gl.Const import UNKNOWN, ALL
from src.gl.Enums import MessageSeverity, Output
from src.gl.Message import Message


class DjangoSanitizerManager(SanitizerManagerPython):

    def __init__(self):
        super().__init__()
        self._fm = DjangoFieldManager(self._parser)

    """
    Find Serializers and their fields
    """

    def _add_enums(self):
        super()._add_enums()

        # A. Get and analyze fields of rest_framework serializers
        self._sanitizers.extend(
            [Sanitizer(E) for E in self._get_sanitizer_definitions('Serializer')])
        self._sanitizers.extend(
            [Sanitizer(E) for E in self._get_sanitizer_definitions('serializers.serializer')])
        self._sanitizers.extend(
            [Sanitizer(E) for E in self._get_sanitizer_definitions('serializers.ModelSerializer')])

        # B. Get and analyze fields of rest_framework serializers descendants
        serializer_descendants = [S.element.name for S in self._sanitizers]
        for serializer_name in serializer_descendants:
            self._sanitizers.extend(
                [Sanitizer(E) for E in self._get_sanitizer_definitions(serializer_name)])

        self._messages.append(Message(f'{len(self._sanitizers)} serializers found to be analyzed.',
                                      MessageSeverity.Completion))

    def _get_fields(self, element: Element) -> list:
        self._w_fields = []
        model_class = None

        # Get code of the serializer class
        snippet = self._parser.get_snippet(find_type=CLASS, path=element.path, find_name=element.name,
                                           delimiters=['('], line_no_start=element.line_no)

        mode = VARIABLE
        first = True

        for line, line_no in snippet:
            # Skip the class
            if first:
                first = False
                continue

            # Get scan mode
            mode = self._get_mode(line, mode)

            # a. List the fields (class vars)
            if mode == VARIABLE:
                F = self._fm.get_field(ContainerType.Serializer, element, line, line_no)

                if F:
                    # Model field may be sane.
                    if F.name in self._sane_model_charfield_names:
                        self._set_field_sane(
                            F, line_no, f'{SANITIZED_BY_MODEL} validation detected in corresponding model field.',
                            SANITIZED_BY_MODEL)
                    else:
                        # Serializer field may be sane (e.g. validator=...)
                        self._sanitize_field(F, SANITIZED_AT_FIELD_LEVEL, line, line_no)
                    if not F.ID:
                        self._messages.append(
                            Message(f'*ERROR: Duplicate names will be overwritten. '
                                    f"Cause: field has no ID at {line_no} of '{F.path}'. ", MessageSeverity.Error))
                    self._w_fields.append(F)

            # b. Methods
            if mode == DEF:
                self._parser.set_line(line)

                # 1. "validate_<field>"
                if self._parser.find_and_set_pos('validate_'):
                    # exact name (when searching "house_number_extension" do not find "house_number")
                    field_name = self._parser.get_next_elem(delimiters=['(']).lstrip('validate_')
                    self._set_fields_sane(SANITIZED_AT_FIELD_LEVEL, line, line_no, element, field_name)

                # 2. "def validate(..):"
                else:
                    method_snippet = self._get_snippet(element.path, mode, 'validate', ['('], line_no)
                    if method_snippet:
                        for l, l_no in method_snippet:
                            self._set_fields_sane(SANITIZED_AT_OBJECT_LEVEL, l, l_no, element)

            # c. class Meta():
            if mode == CLASS:
                self._parser.set_line(line)
                method_snippet = self._get_snippet(element.path, mode, 'meta', [':', '('], line_no)
                if method_snippet:
                    for l, l_no in method_snippet:
                        if self._parser.get_assignment_target(l) == 'model':
                            model_class = self._parser.get_assignment_source(l)
                        self._set_fields_sane(SANITIZED_IN_META, l, l_no, element)

        # If associated model found, set it in the fields
        if model_class:
            for F in self._w_fields:
                F.model_class = model_class

        return self._w_fields

    def _set_fields_sane(self, sani_type, l, l_no: int = 0, element: Element = None, field_name=None):
        """
        Multiple fields can be sanitized in one line.
        """
        # A. Multiple fields
        sanitized = False
        for F_new in self._w_fields:
            made_sane = self._sanitize_field(F_new, sani_type, l, l_no, field_name)
            if not sanitized and made_sane:
                sanitized = True
        if sanitized or not field_name:
            return

        # B. Single Field: updert if it is validated via "validate_myField(...)"

        # Create field
        F_new = self._fm.get_field(
            ContainerType.Serializer, element, l, l_no, field_type=UNKNOWN, field_name=field_name)
        if not F_new:
            return

        # Update field to sane
        F_new = self._set_field_sane(F_new, l_no, f'{sani_type} validation detected.', sani_type)

        # If present in the list: Update
        for F_existing in self._w_fields:
            if F_existing.ID_logical == F_new.ID_logical:
                F_existing.vulnerable = False
                F_existing.title = F_new.title
                return
        # Not present yet: Add
        self._w_fields.append(F_new)

    def _sanitize_field(self, F: Field, sani_type, l, l_no, field_name=None) -> bool:
        # N.B. multiple fields can be sanitized in one line.
        if field_name and F.element.name == field_name or (field_name is None and l.find(F.element.name) > -1):
            if sani_type == SANITIZED_IN_META and self._is_validator_field(l):
                self._set_field_sane(
                    F, l_no, f'{sani_type} Meta validator validation.', sani_type)
                return True
            # Model field may be sane.
            elif F.name in self._sane_model_charfield_names:
                self._set_field_sane(
                    F, l_no, f'{sani_type} validation detected in corresponding model field.', sani_type)
                return True
            # Field-level (e.g. max_length or boolean) sanitization prevails over e.g Object-level sanitizing.
            elif F.vulnerable and self._is_validator_field(l):
                self._set_field_sane(
                    F, l_no, f'{sani_type} validation detected.', sani_type)
                return True
        return False

    def parse_for_validated_serializers(self):
        """
        Parse sources that contains '.is_valid'.
        This step must be executed before parsing for endpoints.
        """
        self._scanner.scan_dir(SearchPattern('.is_valid('), output=Output.Object)
        snippets = {F.path: self._parser.get_snippet(find_type=ALL, path=F.path) for F in self._scanner.findings}
        # Parse endpoints to validators
        [self._parse_for_validated_serializers_in_a_source(path, source_file) for path, source_file in
         snippets.items()]

    def _parse_for_validated_serializers_in_a_source(self, path, source_file):
        self._parser.initialize()
        class_name, class_name_p, method_element = None, None, None

        for line, line_no in source_file:

            # Remember vars to be able to retrieve the serializer_name.
            self._parser.set_assignment(line)

            # To find sanitizers (containing ".is_valid") in called-methods later on,
            # cache the methods containing the validated serializer.
            name = self._parser.get_sanitizer_name(line)
            if name and method_element and method_element.class_name and method_element.method_name:
                logical_method_id = f'{method_element.class_name}|{method_element.method_name}'
                self._sane_methods[logical_method_id] = method_element

            # Remember last class name and -line.
            class_name = self._parser.get_first_elem(line, CLASS, dft=class_name)

            # Start of method
            method_name = self._parser.get_first_elem(line, METHOD)

            # Cache called sanitizer methods (i.e. not the http methods) that contain ".is_valid".
            if method_name:
                if method_name in HttpMethods.all:
                    method_element = None
                else:
                    method_element = Element(
                        input_dir=self._session.input_dir,
                        path=f'{self._session.input_dir}{path}',
                        line_no=line_no,
                        method_name=method_name,
                        class_name=class_name,
                        line=line)
