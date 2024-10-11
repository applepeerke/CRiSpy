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
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.Functions.FindProject import sophisticate_path_name
from src.core.Plugins.FrameworkPluginBase import FM
from src.core.Plugins.SanitizerManagerBase import SanitizerManagerBase
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import CSV_EXT, EMPTY, ALL
from src.gl.Enums import LogLevel, MessageSeverity
from src.gl.Functions import remove_color_code, path_leaf_only
from src.gl.Message import Message
from src.gl.Validate import normalize_dir

PGM = 'EndpointManagerBase'

AuthzM = AuthenticationManager()


class EndpointManagerBase:

    @property
    def messages(self):
        return self._messages

    @property
    def framework_name(self):
        return self._framework_name

    @property
    def fields(self):
        return self._fields

    @property
    def endpoints(self):
        return self._endpoints

    @property
    def sanitizer_manager(self):
        return self._sanitizer_manager

    def __init__(self, framework_name, parser, sanitizer_manager=SanitizerManagerBase()):
        self._framework_name = framework_name
        self._session = Session()
        self._endpoints = {}
        self._sanitizer_manager = sanitizer_manager
        self._sanitizer_names = set()
        self._fields = []
        self._sanitizer_fields = []
        self._model_fields = []

        self._parser = parser
        self._messages = []
        self._var_dict = {}
        self._log_level = LogLevel.Verbose
        self._output_dir = normalize_dir(f'{self._session.log_dir}DataFlow', create=True)
        self._ini_endpoint()
        self._mode = EMPTY
        self._class_stack = []
        self._class_name_prv = EMPTY
        self._class_indent_prv = 0
        self._authentication = set()
        self._permission = set()
        self._authorization = set()
        self._sanitizer_names = set()

    def endpoint_analysis(self):
        raise NotImplementedError

    def _get_endpoints(self, **kwargs):
        raise NotImplementedError

    def _parse_for_endpoints(self, path, source_file, **kwargs):
        raise NotImplementedError

    def _ini_class(self):
        self._authentication = set()
        self._permission = set()
        self._authorization = set()
        self._sanitizer_names = set()

    def _ini_endpoint(self, class_name_prv=None, class_indent_prv=0):
        if class_name_prv:
            self._push_class(class_name_prv, class_indent_prv)
        self._base_route = EMPTY
        self._route = EMPTY
        self._http_method = EMPTY
        self._decorators = {}
        self._element = None
        self._input_sanitizers = None
        self._vulnerable = False

    def _push_class(self, class_name_prv, class_indent_prv):
        """ Save endpoint (higher level) values e.g. for when a helper class is temporary embedded. """
        # Indent <= previous indent: overwrite stack entry, else keep it.
        if self._class_stack:
            d = self._class_stack.pop()  # Previous stack entry
            if d['class_indent_prv'] > class_indent_prv:
                self._class_stack.append(d)  # Keep previous stack entry

        self._class_stack.append({
            'class_name_prv': class_name_prv,
            'class_indent_prv': class_indent_prv,
            'base_route': self._base_route,
            'route': self._route,
            'http_method': self._http_method,
            'decorators': self._decorators,
            'element': self._element,
            'authentication': self._authentication,
            'permission': self._permission,
            'authorization': self._authorization,
            'input_sanitizers': self._input_sanitizers,
            'vulnerable': self._vulnerable,
            'sanitizer_names': self._sanitizer_names
        })

    def _pop_class(self) -> bool:
        d = self._class_stack.pop() if self._class_stack else {}
        if not d:
            return False

        self._class_name_prv = d['class_name_prv']
        self._class_indent_prv = d['class_indent_prv']

        self._base_route = d['base_route']
        self._route = d['route']
        self._http_method = d['http_method']
        self._decorators = d['decorators']
        self._element = d['element']
        self._authentication = d['authentication']
        self._permission = d['permission']
        self._authorization = d['authorization']
        self._input_sanitizers = d['input_sanitizers']
        self._vulnerable = d['vulnerable']
        self._sanitizer_names = d['sanitizer_names']
        return True

    def _create_endpoint(self, path, element: Element) -> str:
        if not element:
            return EMPTY
        endpoint_id = f'{path}:{element.line_no}'  # key
        endpoint = Endpoint(
            element=element,
            method_name=self._http_method or element.method_name,
            route=self._route,
            decorators=self._decorators.values(),
            authentication=self._authentication,
            permission=self._permission,
            authorization=self._authorization,
            input_sanitizers=self._input_sanitizers,
            vulnerable=self._vulnerable
        )
        self._endpoints[endpoint_id] = endpoint
        # Initialize
        self._ini_endpoint()
        return endpoint_id

    def _add_decorator(self, decorator):
        """
        Decorator may be used for non-API methods too. Remember only last one
        """
        p = decorator.find('(')
        key = decorator[:p] if p > -1 else decorator
        self._decorators[key] = decorator

    def _get_endpoint_paths(self, input_names) -> set:
        raise NotImplementedError

    def _get_endpoint_snippets(self, paths) -> dict:
        return {path: self._parser.get_snippet(find_type=ALL, path=f'{self._session.input_dir}{path}') for path
                in paths}

    def write_endpoints(self, endpoints: dict):
        # a. Write Endpoints - also vulnerability
        root_dir = f'{path_leaf_only(self._session.input_dir)}'
        FM.initialize(FindingTemplate.ENDPOINTS)
        rows = [
            [
                sophisticate_path_name(EP.element.path, root_dir, EP.element.line_no),
                # EP.element.path.replace( self._session.input_dir, "../" ),
                EP.route or EP.element.class_name,
                EP.method_name or EP.element.name,
                EP.vulnerable or EP.vulnerable_usage,
                ", ".join(list(EP.input_sanitizers)) if EP.input_sanitizers else EMPTY,
                ", ".join(list(EP.vulnerable_field_names)),
                ", ".join(f'{remove_color_code(M.message)}' for M in EP.messages)
            ] for EP in endpoints.values()
        ]
        # Write path in session
        self._session.endpoints_path = f'{self._output_dir}{FindingTemplate.ENDPOINTS}_{self._framework_name}{CSV_EXT}'
        # Write endpoints analysis
        FM.write_results(
            rows,
            FindingTemplate.ENDPOINTS,
            data_path=self._session.endpoints_path)

    def _add_messages(self, messages: [Message]):
        """
        messages: All messages or completion_messages.
        """
        if self._log_level == LogLevel.Verbose:
            self._messages.extend(messages)
        else:
            [self._messages.append(m) for m in messages if messages and m.severity >= MessageSeverity.Error]
        return
