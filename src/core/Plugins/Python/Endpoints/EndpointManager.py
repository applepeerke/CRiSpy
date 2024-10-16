# ---------------------------------------------------------------------------------------------------------------------
# DjangoEndpointManager.py
# Author      : Peter Heijligers
# Description : EndpointManager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-01-22 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.AuthenticationManager import AuthenticationManager
from src.core.BusinessLayer.AuthorizationManager import AuthorizationManager
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.BusinessLayer.Scanner import Scanner
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.Enums import FrameworkName
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Functions.FindProject import sophisticate_path_name
from src.core.Plugins.Const import CLASS, METHOD, SANITIZED_VIA_VALIDATOR
from src.core.Plugins.EndpointManagerBase import EndpointManagerBase
from src.core.Plugins.Python.DataFlow.DataFlowParser import DataFlowParser
from src.core.Plugins.Python.Endpoints.SanitizerManagerPython import SanitizerManagerPython
from src.core.Plugins.Python.Frameworks.Django.DjangoParser import DjangoParser
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.LogManager import STRIPE
from src.gl.Const import BLANK, EMPTY, CSV_EXT, ALL
from src.gl.Enums import LogLevel, Color, MessageSeverity
from src.gl.Functions import path_leaf_only, loop_increment
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message
from src.gl.Validate import isHardcodedString, normalize_dir

PGM = 'EndpointManager'

PROCESSED = 'Processed'
RETURNED = 'Returned'
USAGE_TYPES = (PROCESSED, RETURNED)
NO_USAGE = 'Serializer seems not to be used with input in an endpoint'

scanner: Scanner
AuthoM = AuthorizationManager()
AuthzM = AuthenticationManager()
FM = Findings_Manager()


class EndpointManager(EndpointManagerBase):

    @property
    def frameworks(self):
        return self._frameworks

    """
    Setters
    """

    @frameworks.setter
    def frameworks(self, value):
        self._frameworks = value

    def __init__(self, framework_name, title=EMPTY):
        super().__init__(framework_name, DjangoParser(), SanitizerManagerPython())
        self._title = title
        self._frameworks = {}
        self._usage_in_endpoint_dict = {}
        self._log_level = LogLevel.Verbose
        self._first_write = True
        self._parameter_flows = []
        self._endpoint_usage_rows = []
        self._mode = None
        self._CM = None
        self._col_names = FindingTemplate.template_headers[FindingTemplate.REST_FRAMEWORK_ENDPOINTS_DATA_FLOW]
        self._root_dir = f'{path_leaf_only(self._session.input_dir)}'
        if self._session.db:
            from src.db.BusinessLayer.XRef.XRef_Class_manager import XRef_Class_manager
            self._CM = XRef_Class_manager(self._session.db)

        self._validator_field_names = []
        self._has_marshmallow = False
        self._output_dir = normalize_dir(f'{self._session.log_dir}DataFlow', create=True)

    def endpoint_analysis(self):
        raise NotImplementedError

    """
    Fields
    """

    def _add_fields(self, model_manager):
        self._fields = []
        self._sanitizer_fields = []
        self._model_fields = []

        # a. Model fields
        self._add_model_fields(model_manager)
        # b. Sanitizer (serializer) field, Enums.
        self._add_sanitizer_fields(model_manager)
        # c. Merge fields if needed
        self._merge_all_fields()

    def _add_model_fields(self, model_manager):
        model_manager.find_fields()
        self._model_fields.extend(model_manager.fields)
        self._add_messages(model_manager.messages)

    def _add_sanitizer_fields(self, model_manager):
        """ Only for Django and FastApi frameworks. Rest and Pydantic should pass """
        pass

    def _merge_all_fields(self):
        """ Merge Model and Sanitizer (Serializer) fields """
        self._fields = []
        prefix = EMPTY
        if not self._model_fields and not self._sanitizer_fields:
            self._messages.append(Message(
                f'{Color.GREEN}No{Color.NC} Serializer or Model fields found. ', MessageSeverity.Completion))
            return

        if not self._model_fields:
            self._fields.extend(self._sanitizer_fields)
        elif not self._sanitizer_fields:
            self._fields.extend(self._model_fields)
        else:
            self._fields.extend(self._merge_fields())
            prefix = 'After merging of Model and Sanitizer fields, '

        # Sanitize fields that are validated with a validator method at a higher-than-serializer level.
        self._sanitize_validator_fields(prefix)

        vulnerable_count = sum(F.vulnerable for F in self._fields)

        # Output
        # - Framework fields
        #   Order by: [path, field_name, ID] (should be unique)
        self._fields = sorted(self._fields, key=lambda x: (x.element.path, x.element.name, x.ID))

        # - Completion message - merge
        self._messages.append(Message(f'{Color.GREEN}{STRIPE}{Color.NC}', MessageSeverity.Completion))
        if vulnerable_count == 0:
            self._messages.append(Message(
                f'{prefix}{Color.GREEN}No{Color.NC}  '
                f'vulnerable string fields found. ', MessageSeverity.Completion))
        else:
            self._messages.append(Message(
                f'{prefix}{Color.ORANGE}{vulnerable_count} '
                f'{Color.RED}vulnerable{Color.NC} string fields found. ', MessageSeverity.Completion))

    def _sanitize_validator_fields(self, prefix=EMPTY):
        """
        Validators can occur at another level than Serializer, so this is done here.
        """
        if not self._validator_field_names:
            return

        sanitized_count = 0
        for F in self._fields:
            if F.vulnerable:
                if F.name in self._validator_field_names:
                    sanitized_count += 1
                    F.vulnerable = False
                    F.title = f'{SANITIZED_VIA_VALIDATOR} validation detected.'
        # Completion message
        if sanitized_count > 0:
            self._messages.append(Message(
                f'{prefix}{sanitized_count} '
                f'{Color.GREEN}validator-validated{Color.NC} string fields found. ', MessageSeverity.Completion))

    def _merge_fields(self) -> list:
        model_field_IDs_dict = {F.ID_logical: F for F in self._model_fields}
        self._sanitizer_field_IDs_dict = {F.ID_logical: F for F in self._sanitizer_fields}

        # 1) Add sane model_fields
        out = [F for F in model_field_IDs_dict.values() if not F.vulnerable]
        out_ids = [F.ID_logical for F in out]

        # 2) Add sane serializer_fields (unique)
        out.extend([
            F for F in self._sanitizer_field_IDs_dict.values() if not F.vulnerable and F.ID_logical not in out_ids])
        out_ids = [F.ID_logical for F in out]

        # 3) Add vulnerable model_fields (unique)
        out.extend([F for F in model_field_IDs_dict.values() if F.ID_logical not in out_ids])
        out_ids = [F.ID_logical for F in out]

        # 4) Add vulnerable serializer_fields (unique)
        out.extend([F for F in self._sanitizer_field_IDs_dict.values()
                    if F.ID_logical not in out_ids
                    and F.name not in self._sanitizer_manager.sane_model_charfield_names])
        return out

    # ToDo: Better solution for marshmallow sanitizers in decorators. This should also be a inherited method.
    def _get_endpoints(self, framework_plugin, class_vulnerability_dict):
        """ Django and FastAPI """
        input_names = framework_plugin.input_names
        api_method_names = framework_plugin.api_method_names
        self._has_marshmallow = self._frameworks.get(FrameworkName.Marshmallow)

        if not self._framework_name or not input_names or not api_method_names:
            raise GeneralException(
                f"{__name__}: Required input is not present for framework '{self._framework_name}'.")

        # Get sanitizer methods (containing ".is_valid")
        if self._frameworks.get(FrameworkName.Django):
            self._sanitizer_manager.parse_for_validated_serializers()

        # a. Create endpoints
        self._endpoints = {}
        self._messages = []

        endpoint_source_files = self._get_endpoint_snippets(self._get_endpoint_paths(input_names))
        for path, source_file in endpoint_source_files.items():  # e.g. ../views.py
            self._parse_for_endpoints(path, source_file, api_method_names, class_vulnerability_dict)

        # b. Add parameter-flows to endpoint and Write them to Excel/Console.
        self._set_endpoints_usage(data_path=self._get_flow_analysis_output_path())

        # c. Evaluate the endpoints.
        #    Add validation messages, optionally update vulnerability (must be done after setting parameter-flows).
        for endpoint_id, EP in self._endpoints.items():
            self._endpoints[endpoint_id] = self._evaluate_endpoint_validation(EP)

        # Completion and error messages
        self._messages.append(
            Message(f'{len(self.endpoints)} {self._framework_name} endpoints found.', MessageSeverity.Completion))

    def _parse_for_endpoints(self, path, source_file, api_method_names=None, class_vulnerability_dict=None):
        """ Parse the view that contains the api methods."""
        self._parser.initialize()
        self._ini_endpoint()
        class_name, class_name_p, endpoint_id, sanitizer, method_element = None, None, None, None, None
        method_indent, class_indent_p = 0, 0

        for line, line_no in source_file:
            current_indent = len(line) - len(line.lstrip(BLANK))
            # Level breaks
            # a. End of method (@api_* method): Add analyzed validation messages and sanitizers
            if current_indent <= method_indent and endpoint_id:
                self._add_endpoint(endpoint_id)
                endpoint_id = None

            # b. End of class: reset endpoint values belonging to parent class.
            #    E.g. Think of a helper class embedded within another class containing endpoints.
            while current_indent <= class_indent_p and class_name and self._pop_class():
                class_name = self._class_name_prv
                class_indent_p = self._class_indent_prv

            # Remember vars to be able to retrieve the input_serializer_name.
            self._parser.set_assignment(line)

            # Add sanitizer
            # (Django: "serializer_class" or first serializer with ".is_valid" method,
            #   and also add sanitizer-methods )
            name = self._parser.get_sanitizer_name(line)
            if name:
                self._sanitizer_names.add(name)

            # Remember last parent class name and -line of the endpoint method.
            class_name_p = class_name
            class_name = self._parser.get_first_elem(line, CLASS, dft=class_name)
            if class_name != class_name_p:
                self._ini_endpoint(class_name_p, class_indent_p)  # Also push previous class to stack
                self._ini_class()
                class_indent_p = len(line) - len(line.lstrip(BLANK))

            # Remember permission_classes and authentication_classes
            self._add_auth(line)

            # Remember decorators just before endpoint
            decorator = line.lstrip()
            if decorator.startswith('@'):
                method_indent = len(line) - len(line.lstrip(BLANK))
                # (Marshmallow may have Schema sanitizers in decorators)
                self._add_decorator(decorator)
                if self._framework_name in (FrameworkName.Django, FrameworkName.Rest) \
                        and decorator.startswith('@api_'):
                    self._is_endpoint = True

            # Start of method
            method_name = self._parser.get_first_elem(line, METHOD)
            if method_name:
                method_element = Element(
                    input_dir=self._session.input_dir,
                    path=f'{self._session.input_dir}{path}',
                    line_no=line_no,
                    method_name=method_name,
                    class_name=class_name,
                    line=line)
                # Start of endpoint?
                # Endpoints = Methods (post/get/put, *.post/*.get/*.put (fastApi)).
                # a. Module contains endpoint;
                # b. Not Django and derived from "rest_framework.request":
                #       may have other method name and e.g. contain "request"
                if self._is_endpoint \
                        or method_name in api_method_names \
                        or (self._framework_name != FrameworkName.Django and 'req' in line.lower()):
                    # Add optional authz in this class and in all of its super classes.
                    self._add_super_authz(method_element.class_name)
                    endpoint_id = self._create_endpoint(path, method_element)
            if endpoint_id:
                # Endpoint mode. Analyze line. For now only Django.
                # E.g. is ".valid_data" used (ok) or ".data" (error)
                self._endpoints[endpoint_id] = self._add_validation_items(line, self._endpoints[endpoint_id])

        # Last time in source file: Resolve pending actions
        self._add_endpoint(endpoint_id)

    def _ini_endpoint(self, class_name_prv=None, class_indent_prv=0):
        """
        Initialize at "def" (or "class") point.
        self._sanitizers is initialized elsewhere.
        """
        super()._ini_endpoint(class_name_prv, class_indent_prv)
        self._is_endpoint = False

    def _add_endpoint(self, endpoint_id):
        if not endpoint_id:
            return

        # Input sanitizer names
        self._endpoints[endpoint_id].input_sanitizers = self._sanitizer_names if self._sanitizer_names else None
        self._ini_endpoint()

    def _add_decorator(self, decorator):
        """
        Decorator may be used for non-API methods too. Remember only last one
        """
        super()._add_decorator(decorator)
        if self._has_marshmallow:
            self._add_marshmallow_sanitizer_names(decorator)

    def _add_marshmallow_sanitizer_names(self, line):
        """
        Schema may be present in a decorator
        """
        s = line.find('(')
        e = line.find(')')
        if not -1 < s < e:
            return

        names = line[s + 1:e].split(',')
        names = [n.strip() for n in names]
        sanitizer_names = [name for name in names if name.endswith('Schema')]
        for s in sanitizer_names:
            self._sanitizer_names.add(s)

    def _add_auth(self, line):
        """
        Analyze a source line
        """
        # Django authentication
        [self._authentication.add(a) for a in self._get_list('authentication_classes', line)]
        # Django permission
        [self._permission.add(p) for p in self._get_list('permission_classes', line)]
        # Company authorizations from csv, e.g. {"KPN": "required_scope"}
        [self._add_authorization(pattern, line) for pattern in AuthoM.patterns if pattern in line]

    def _set_endpoints_usage(self, data_path):
        if not self._endpoints:
            return

        self._messages.append(Message(f'\n{Color.GREEN}Data flows{Color.NC}', MessageSeverity.Completion))

        # a. Add EM parameter flows and method usage
        self._set_parameter_flows(self._log_level, self._root_dir, framework=self._framework_name)

        # b. Add errors and method usage to messages
        self._messages.append(
            Message(f'\n{Color.GREEN}Endpoint vulnerability{Color.NC}', MessageSeverity.Completion))

        # c. Write usage to csv
        if data_path:
            self._first_write = True
            c_names = self._col_names if self._first_write else None
            CsvManager().write_rows(
                self._endpoint_usage_rows, col_names=c_names, data_path=data_path, add_id=False)
            self._first_write = False

    def _set_parameter_flows(self, log_level, root_dir, debug_mode=False, framework=FrameworkName.Unknown):
        self._log_level = log_level
        self._parameter_flows = []
        self._endpoint_usage_rows = []
        self._DF_parser = DataFlowParser()

        for EP in self._endpoints.values():
            # a. Set vulnerable if linked to a vulnerable serializer.
            linked_to_vulnerable = self._sanitizer_manager.is_vulnerable(EP.input_sanitizers)
            if linked_to_vulnerable:
                EP.vulnerable_sanitizer = True
                EP.vulnerable = True
            # b. Set ParameterFlows, cascade "linked to a vulnerable serializer" to them and their DataFlows.
            EP.parameter_flows = self._DF_parser.get_parameter_flows(
                EP.element, linked_to_vulnerable, debug_mode=debug_mode, session=self._session, framework=framework)

            # c. Get/Set/Output endpoint usage
            self._endpoint_usage(EP, root_dir)

    def _endpoint_usage(self, EP, root_dir):
        """
        Add usage (for merging with field input analysis)
        """
        # validate
        if not EP.parameter_flows:
            E = EP.element
            sophisticated_dir = E.path.replace(self._session.input_dir[:-1], "..") \
                if self._session.input_dir else E.path
            self._messages.append(Message(
                f'{Color.BLUE}Endpoint{Color.NC} {sophisticated_dir} '
                f'{Color.BLUE}class {Color.NC}{E.class_name} '
                f'{Color.BLUE}method{Color.NC} {E.method_name} '
                f'{Color.BLUE}has {Color.GREEN}no{Color.BLUE} parameter flows.{Color.NC}', MessageSeverity.Error))
            return

        # a. Set endpoint usage
        self.set_endpoint_usage(EP.element.class_name, EP.input_sanitizers, EP.called_methods, EP.returned_outputs)
        # b. Add method usage to messages
        self._add_endpoint_usage_messages(EP, root_dir)
        # c. Add method usage to .csv rows
        self._add_endpoint_usage_rows(EP.input_sanitizers, root_dir)

    def _add_endpoint_usage_messages(self, EP, root_dir):
        called_methods = set()
        returned_outputs = set()
        E = EP.element

        # Add messages
        for Flow in EP.parameter_flows:
            [called_methods.add(m) for m in Flow.called_methods]
            [returned_outputs.add(r) for r in Flow.returned_outputs]

            method_fragment = f'{Color.BLUE}is passed to methods{Color.NC} {Flow.called_methods}' \
                if Flow.called_methods else f'{Color.BLUE}does not flow outside the endpoint method{Color.NC}'

            output_fragment = f'{Color.BLUE}is returned in{Color.NC} {Flow.returned_outputs}' \
                if Flow.returned_outputs else f'{Color.BLUE}is NOT returned{Color.NC}'

            self._messages.append(
                Message(f'{Color.BLUE}Endpoint{Color.NC} {sophisticate_path_name(E.path, root_dir)} '
                        f'{Color.BLUE}class{Color.NC} {E.class_name} '
                        f'{Color.BLUE}method{Color.NC} {E.method_name} '
                        f'{Color.BLUE}input parameter{Color.NC} {Flow.input_parameter} {method_fragment} '
                        f'{Color.BLUE}and{Color.NC} {output_fragment}',
                        MessageSeverity.Completion))

    def _add_endpoint_usage_rows(self, sanitizer_names, root_dir):
        for Flow in self._parameter_flows:
            ms = Flow.method_signature
            sanitizer_names = ', '.join(sanitizer_names) if sanitizer_names else EMPTY
            self._endpoint_usage_rows.append(
                [sophisticate_path_name(ms.path, root_dir),
                 ms.class_name, ms.method_name, Flow.input_parameter,
                 Flow.called_methods, Flow.returned_outputs, ms.line_no_start, sanitizer_names])

    """
    Set Sanitizer usage in endpoint
    """

    def set_endpoint_usage(self, endpoint_class_name, sanitizer_names, called_methods, returned_outputs):
        """
        Summarize all get/put/post analyses to the associated serializer
        :param endpoint_class_name: ApiMethod class name where the get/put/post method is in.
        :param sanitizer_names: Class names linked to the endpoint input.
        :param called_methods: Methods called in the get/put/post method influenced by input.
        :param returned_outputs: Output returned which is influenced by input.
        :return:
        """
        if not endpoint_class_name or not sanitizer_names:
            return None

        # Remember if
        # (a) Endpoint input has been passed to a method, or
        # (b) Endpoint input was returned (reflected)
        passed = True if called_methods else False
        returned = True if returned_outputs else False
        for sanitizer_name in sanitizer_names:
            if sanitizer_name in self._usage_in_endpoint_dict.keys():
                self._usage_in_endpoint_dict[sanitizer_name][PROCESSED] = passed \
                    if self._usage_in_endpoint_dict[sanitizer_name][PROCESSED] is False else True
                self._usage_in_endpoint_dict[sanitizer_name][RETURNED] = returned \
                    if self._usage_in_endpoint_dict[sanitizer_name][RETURNED] is False else True
            else:
                self._usage_in_endpoint_dict[sanitizer_name] = {PROCESSED: passed, RETURNED: returned}

    """
    Get Sanitizer usage in endpoint
    """

    def get_endpoint_input_parent_usage(self, parent_names: list) -> str:
        """
        :param parent_names: (super)classes and fields of type sanitizer (e.g. Django serializer)
        that are associated with endpoint sanitizer
        :return: 'Processed and Returned', 'Processed' or 'Returned'.
        """
        if not parent_names:
            return NO_USAGE  # error / not used

        processed, returned = False, False
        for s in parent_names:
            if s in self._usage_in_endpoint_dict:
                processed = self._usage_in_endpoint_dict[s][PROCESSED] if not processed else processed
                returned = self._usage_in_endpoint_dict[s][RETURNED] if not returned else returned

        return f'Serializer fields {PROCESSED} and {RETURNED} in an endpoint.' if (processed and returned) \
            else f'Serializer fields {PROCESSED} in, not returned from an endpoint.' if processed \
            else f'Serializer fields {RETURNED} from, not processed in an endpoint.' if returned \
            else NO_USAGE

    """
    Authentication
    """

    def _add_super_authz(self, class_name):
        """ Look for authz in all super classes """
        if not class_name or not self._CM:
            return
        relative_paths = self._CM.get_relative_paths_of_class_supers(class_name)
        if not relative_paths:
            return

        for relative_path in relative_paths:
            snippet = self._parser.get_snippet(find_type=ALL, path=f'{self._session.input_dir}{relative_path}')
            [self._add_auth(line) for line, line_no in snippet]
        return

    """
    Authorization
    """

    def _add_authorization(self, pattern, line):
        authorization = self._parser.get_assignment_source_by_find_string(pattern, line)
        if authorization:
            authorization = '*Dynamic' if not isHardcodedString(authorization) else authorization
            self._authorization.add(authorization)

    def _get_flow_analysis_output_path(self) -> str or None:
        if self._framework_name in (FrameworkName.Rest, FrameworkName.Django):
            return f'{self._output_dir}{FindingTemplate.REST_FRAMEWORK_ENDPOINTS_DATA_FLOW}{self._title}{CSV_EXT}'
        else:
            return None

    @staticmethod
    def _get_list(find_string, line) -> list:
        """
        "permission_classes" and "authentication_classes" are in a list
        """
        p = line.find(find_string)
        if p == -1:
            return []
        end_hook = ']'
        s = line.find('[', p)
        if s == -1:
            s = line.find('(', p)
            if s == -1:
                return []
            end_hook = ')'
        s += 1
        e = line.find(end_hook, s)
        elems = line[s:e] if e > s > -1 else None
        names = elems.split(',') if elems else []
        return [n for n in names if n]

    def _get_endpoint_paths(self, input_names) -> set:
        global scanner
        scanner = Scanner(base_dir=self._session.input_dir, file_type='py')
        scanner.initialize_scan()

        endpoint_containing_paths = set()
        FM.initialize(FindingTemplate.FINDINGS, self._session.input_dir)
        for fw_input in input_names:
            self._paths = set()
            findings = self._scan_for_input_names(fw_input)
            # Get derived classes from finding lines (e.g. "BaseView" from "BaseView(APIView)") recursively.
            while findings and loop_increment(f'{__name__}.get_endpoint_paths'):
                class_names = self._get_derived_class_names(findings)
                paths_before = len(self._paths)
                for class_name in class_names:
                    findings = self._scan_for_input_names(class_name)
                if len(self._paths) == paths_before:
                    findings = []
            # Completion
            if self._paths:
                self._messages.append(Message(
                    f"{len(self._paths)} source files added to evaluate using '{fw_input}'",
                    MessageSeverity.Completion))
            [endpoint_containing_paths.add(p) for p in self._paths]
        return endpoint_containing_paths

    def _scan_for_input_names(self, fw_input) -> list:
        """
        For an input name (e.g. "APIView" return all (derived) paths.
        If no path is added (all were present already), return no findings to indicate while loop to end.
        """
        findings = scanner.scan_dir_to_findings(SearchPattern(fw_input))
        for path in FM.get_paths(findings):
            self._paths.add(path.replace(self._session.input_dir, EMPTY))
        return findings

    def _get_derived_class_names(self, findings) -> set:
        """
        Get derived classes (e.g. "BaseView" in finding "class BaseView(APIView)")
        """
        class_names = set()
        for F in findings:
            # Get derived class name ("BaseView")
            if CLASS in F.line:
                if self._parser.find_and_set_pos(CLASS, set_line=F.line, just_after=True):
                    class_name = self._parser.get_next_elem(delimiters=['('], LC=False)
                    if class_name:
                        class_names.add(class_name)
        return class_names

    def _add_validation_items(self, line, endpoint: Endpoint) -> Endpoint:
        """ During endpoint parsing add validation items (like ".validated_data" vs. ".data"). """
        return endpoint

    @staticmethod
    def _evaluate_endpoint_validation(endpoint: Endpoint) -> Endpoint:
        """ Evaluate validation items gathered during endpoint parsing (like ".validated_data" vs. ".data"). """
        return endpoint

    def _add_messages(self, messages: [Message]):
        """
        messages: All messages or completion_messages.
        """
        if self._log_level == LogLevel.Verbose:
            self._messages.extend(messages)
        else:
            [self._messages.append(m) for m in messages if messages and m.severity >= MessageSeverity.Error]
        return
