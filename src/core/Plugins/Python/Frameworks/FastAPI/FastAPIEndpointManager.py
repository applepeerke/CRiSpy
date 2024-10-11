from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.Enums import FrameworkName
from src.core.Plugins.Const import SANITIZED_BY_NOT_EXPOSED, SANITIZED_BY_SANE_TYPE, SANITIZED_BY_GET_METHOD
from src.core.Plugins.Python.Endpoints.EndpointManager import EndpointManager, AuthzM
from src.core.Plugins.Python.Frameworks.FastAPI.FastAPIManager import FastAPIManager
from src.core.Plugins.Python.Frameworks.Pydantic.PydanticFieldManager import PydanticFieldManager
from src.core.Plugins.Python.Frameworks.Pydantic.PydanticModelManager import PydanticModelManager
from src.db.DataLayer.Model.Model import Model
from src.db.DataLayer.Table import Table
from src.gl.Const import EMPTY
from src.gl.Functions import get_names_from_line

model = Model()
class_dict = model.get_att_order_dict(Table.XRef_Classes, zero_based=False)

PydanticM = PydanticFieldManager()
FastAPIM = FastAPIManager()


class FastAPIEndpointManager(EndpointManager):

    def __init__(self, framework_name):
        super().__init__(framework_name)

    def endpoint_analysis(self):
        framework_name = EMPTY
        framework = self.frameworks.get(FrameworkName.FastApi)
        # a. Scan on api_method names, input_names (FastAPI)
        if framework:
            framework_name = FrameworkName.FastApi
            FastAPIM.is_framework(self._session, framework.scanner)

        # b. Fields (Pydantic)
        self._fields = []
        framework = self.frameworks.get(FrameworkName.Pydantic)
        self._add_fields(PydanticModelManager(framework))

        #  - Sanitize fields that are validated with a validator method at a higher-than-serializer level.
        self._validator_field_names = PydanticM.find_field_validators(framework.scanner)
        self._sanitize_validator_fields()
        self._sanitize_sane_type_fields()

        # c. Retrieve all endpoints (with parameter flows)
        if framework_name == FrameworkName.FastApi:
            class_vulnerability_dict = {F.model_class: False for F in self._fields if F.model_class}
            for F in self._fields:
                if F.model_class and F.vulnerable is True:
                    class_vulnerability_dict[F.model_class] = True
            self._get_endpoints(framework_plugin=FastAPIM, class_vulnerability_dict=class_vulnerability_dict)
            self._set_endpoints_vulnerability()
            self._set_fields_without_endpoint_sane(class_vulnerability_dict)
            self._set_fields_with_get_endpoint_sane()

    def _sanitize_sane_type_fields(self):
        """ Enums """
        enums: [Element] = self._sanitizer_manager.get_enum_definitions(self._session.input_dir)
        self._fields = [PydanticM.set_field_sane(F, SANITIZED_BY_SANE_TYPE)
                        if (F.vulnerable and F.field_type in [E.class_name for E in enums])
                        else F for F in self._fields]

    def _set_endpoints_vulnerability(self):
        parent_vulnerable_field_names = self._get_parent_vulnerable_field_names()
        for EP in self._endpoints.values():
            if not EP.input_sanitizers:
                continue
            for sanitizer_name in EP.input_sanitizers:
                if sanitizer_name in parent_vulnerable_field_names:
                    EP.vulnerable = True
                    EP.vulnerable_sanitizer = True
                    vulnerable_field_names = parent_vulnerable_field_names.get(sanitizer_name, set())
                    for name in vulnerable_field_names:
                        EP.vulnerable_field_names.add(name)

    def _set_fields_without_endpoint_sane(self, class_vulnerability_dict):
        """
        If there are endpoints with vulnerable fields, and all endpoints are linked to a sanitizer,
        we can assume the other fields are not exposed in an endpoint.
        """
        if not all(EP.input_sanitizers for EP in self._endpoints.values()):
            return
        vulnerable_field_names = {n for EP in self._endpoints.values() for n in EP.vulnerable_field_names}
        if not vulnerable_field_names:
            return
        # Get field types that are vulnerable classes
        vulnerable_class_names = {
            class_name for class_name, vulnerable in class_vulnerability_dict.items() if vulnerable
        }
        self._fields = [PydanticM.set_field_sane(F, SANITIZED_BY_NOT_EXPOSED)
                        if (F.vulnerable and F.name not in vulnerable_field_names
                            and F.parent_name not in vulnerable_class_names
                            and F.field_type not in vulnerable_class_names)
                        else F for F in self._fields]

    def _set_fields_with_get_endpoint_sane(self):
        """
        We assume that fields only used in GET methods are not vulnerable.
        """
        vulnerable_method_field_names = {
            n for EP in self._endpoints.values() for n in EP.vulnerable_field_names if EP.method_name != 'get'}
        self._fields = [PydanticM.set_field_sane(F, SANITIZED_BY_GET_METHOD, suffix=False)
                        if (F.vulnerable and F.name not in vulnerable_method_field_names)
                        else F for F in self._fields]

    def _get_parent_vulnerable_field_names(self) -> dict:
        """ list vulnerable fields per parent (like a serializer) """
        # ToDo: inheritance, e.g. serializer may use classes that are potential vulnerable.
        # Initialize dict with vulnerable parent_names
        vulnerable_parents = {F.parent_name: set() for F in self._fields if F.parent_name and F.vulnerable is True}
        # Populate parents with vulnerable fields
        for F in self._fields:
            if F.parent_name and F.vulnerable is True:
                vulnerable_parents[F.parent_name].add(F.name)
        return vulnerable_parents

    def _parse_for_endpoints(self, path, source_file, api_method_names=None, class_vulnerability_dict=None):
        """
        get endpoint = [Element] that point to api endpoint (get/put/post)
        """
        # Take all sanitizers/serializers, vulnerable or not.
        self._input_sanitizer_names = [
            class_name for class_name, vulnerable in class_vulnerability_dict.items()] \
            if class_vulnerability_dict \
            else []

        decorators, self._authentication, self._permission, self._authorization = [], set(), set(), set()
        is_method_endpoint = False
        method_key, input_sanitizer_name = EMPTY, EMPTY

        for line, line_no in source_file:
            # Look for decorators (@router)
            decorator = line.lstrip()
            if decorator.startswith('@'):
                decorators.append(decorator)
                is_method_endpoint = any(f'.{m}' in decorator for m in api_method_names)

            # Endpoints = Methods (*.post/*.get/*.put/*.patch).
            if is_method_endpoint:
                # Authorization
                scopes = self._get_authorization(line, 'scopes=')
                self._add_auth(line)  # Remember custom patterns
                # Add Endpoint
                method_key = f'{path}:{line_no}'  # key
                self._endpoints[method_key] = Endpoint(
                    element=Element(
                        input_dir=self._session.input_dir,
                        path=f'{self._session.input_dir}{path}',
                        line_no=line_no,
                        line=line),
                    input_sanitizers=None,
                    method_name=self._get_method_name(line),
                    route=self._get_route(line),
                    output_sanitizer=self._get_output_sanitizer_name(line),
                    decorators=decorators,
                    authentication=self._authentication,
                    permission=scopes,
                    authorization=scopes
                )
            else:  # method endpoint line contains model definitions, so skip this
                # look for input sanitizer injected in in "def" line after endpoint definition.
                # if ' def ' in line:
                self._try_to_add_input_sanitizer_name(line, method_key)

            # initialize
            decorators = []
            is_method_endpoint = False
            self._authentication = set()
            self._permission = set()
            self._authorization = set()

    def _try_to_add_input_sanitizer_name(self, line, method_key):
        # Validate
        if not self._endpoints.get(method_key):
            return
        # From the line get all names that are known as input sanitizers.
        input_sanitizer_names = {
            input_sanitizer_name for name in get_names_from_line(line, return_too=False)
            for input_sanitizer_name in self._input_sanitizer_names if name == input_sanitizer_name
        }
        if not input_sanitizer_names:
            return
        # Add found input sanitizers to the endpoint set.
        if not self._endpoints[method_key].input_sanitizers:
            self._endpoints[method_key].input_sanitizers = input_sanitizer_names
        else:
            for name in input_sanitizer_names:
                self._endpoints[method_key].input_sanitizers.add(name)
        return

    @staticmethod
    def _get_input_sanitizer_from_names(sanitizers) -> str or None:
        """  First try a name containing 'input'. Else the longest match counts."""
        sanitizer = None
        for s in sanitizers:
            if 'input' in s.lower():
                return s
            if not sanitizer or len(s) > len(sanitizer):
                sanitizer = s
        return sanitizer

    def _set_parameter_flows(self, log_level, root_dir, debug_mode=False, framework=None):
        self._log_level = log_level

        for EP in self.endpoints.values():
            # Set vulnerable if linked to a vulnerable serializer.
            if self._sanitizer_manager:
                if self._sanitizer_manager.is_vulnerable(EP.input_sanitizers):
                    EP.vulnerable = True
                    EP.vulnerable_sanitizer = True

    def _add_auth(self, line):
        """
        Analyze a source line on authentication and authorization
        """
        [self._add_authentication(line, pattern) for pattern in AuthzM.patterns if pattern in line]

    def _add_authentication(self, line, pattern):
        """ find_string: custom find string like "authz" """
        """ Example: @router.post(..., dependencies=[..., relaxed_security(security.authz.has_scopes(),]) """
        p = line.find(pattern)
        if p == -1:
            return  # E.g. "authz" not found
        # Between "."?
        item = self._get_between(line, p, '.')
        if not item:
            item = self._get_between(line, p, '(', ')')
        if not item:
            item = self._get_between(line, p, '[', ']')
        if item:
            self._authentication.add(item)

    @staticmethod
    def _get_authorization(line, find_string) -> set:
        """ Example: @router.post(..., dependencies=[..., scopes=[security.UserScope.UPDATE.value]), ]) """
        p = line.find(find_string)
        if p == -1:
            return EMPTY
        s = p + len(find_string)
        e = line.find(']', p)
        if e == -1:
            e = line.find(',', p)
        scopes = line[s:] if e == -1 else line[s:e + 1]
        if scopes.startswith('[') and scopes.endswith(']'):
            return set(scopes[1:-1].split(','))
        else:
            return {scopes}

    @staticmethod
    def _get_method_name(line) -> str:
        """ Example: @router.post(...) """
        s = line.find('.')
        if s == -1:
            return EMPTY
        e = line.find('(', s)
        return EMPTY if e == -1 else line[s + 1:e]

    def _get_output_sanitizer_name(self, line) -> str:
        """ Example: @router.patch("/{session_id}", response_model=List[has_dbl.SessionSerializer],... """
        find_string = 'response_model='
        s = line.find(find_string)
        if s == -1:
            return EMPTY
        s += len(find_string) - 1
        sanitizer_name = self._get_parameter(line, s)
        p = sanitizer_name.find('[')
        if p > -1:
            sanitizer_name = self._get_between(line, p + 1, '[', ']')
        p = sanitizer_name.find('.')
        if p > -1:
            sanitizer_name = sanitizer_name[p + 1:]
        return sanitizer_name

    def _get_route(self, line) -> str:
        """ Example: @router.post("/invoice", ...) """
        s = line.find('(')
        return self._get_parameter(line, s)

    @staticmethod
    def _get_parameter(line, s):
        if s < 0:
            return EMPTY
        e = line.find(',', s)
        if e == -1:
            e = line.find(')', s)
            if e == -1:
                return EMPTY
        #  may contain "( # type: ignore "v1/myroute", ...)"
        apo = '"'
        s1 = line.find(apo, s)
        if s1 == -1:
            apo = '\''
            s1 = line.find(apo, s)
        e1 = line.find(apo, s1 + 1)
        return line[s1 + 1:e1] if -1 < s1 < e1 else line[s + 1:e].strip()

    @staticmethod
    def _get_between(line, p, left_char, right_char=None) -> str:
        s = line.rfind(left_char, 0, p)
        e = line.find(right_char or left_char, p)
        return line[s + 1:e] if s > -1 and e > -1 else EMPTY
