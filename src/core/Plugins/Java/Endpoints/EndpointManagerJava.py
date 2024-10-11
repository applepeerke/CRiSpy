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
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.Enums import FrameworkName
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import METHOD
from src.core.Plugins.EndpointManagerBase import EndpointManagerBase
from src.core.Plugins.Enums import HttpMethods
from src.core.Plugins.Java.Enums import AccessModifier, NonAccessModifier
from src.core.Plugins.Java.Frameworks.Spring.SpringSanitizerManager import SpringSanitizerManager
from src.core.Plugins.Java.Functions import remove_optional_type_def, get_class_name
from src.gl.Const import BLANK, EMPTY, APOSTROPHES
from src.gl.Enums import MessageSeverity, Output
from src.gl.Message import Message
from src.gl.Parse.Parser_Java import Parser_Java

PGM = 'EndpointManager'
CLASS = 'class '
REQUEST_MAPPING = '@RequestMapping'
BODY = '@Body'


class EndpointManagerJava(EndpointManagerBase):

    def __init__(self, framework_name, scanner):
        super().__init__(framework_name, Parser_Java(), SpringSanitizerManager(scanner))
        self._route_findings = []
        self._scanner = scanner
        self._pattern = None
        self._input_sanitizer = None
        self._authorization = set()

    def endpoint_analysis(self):
        # a. Find routes (endpoints base)
        self._pattern = REQUEST_MAPPING
        self._scanner.scan_dir(SearchPattern(self._pattern), output=Output.Object)
        if not self._scanner.findings:
            self._pattern = BODY
        self._scanner.scan_dir(SearchPattern(self._pattern), output=Output.Object)
        self._route_findings = self._scanner.findings
        # b. Get sanitizers (parse from source)
        self._get_sanitizers()
        # c. Get endpoints (parse from source)
        self._get_endpoints()

    def _find_route_from_method(self, f) -> set:
        # From method finding, find route
        return {rf for rf in self._route_findings if rf.path == f.path}

    def _get_sanitizers(self):
        if self._framework_name == FrameworkName.Spring:
            self._sanitizer_manager.set_validators(self._parser)

    def _get_endpoints(self, **kwargs):
        endpoint_source_files = self._get_endpoint_snippets(self._get_endpoint_paths(self._route_findings))
        # Parse endpoints
        for path, source_file in endpoint_source_files.items():
            self._parse_for_endpoints(path, source_file, **kwargs)
        # Set vulnerability of fields that are complex types.
        self._sanitizer_manager.sanitize_fields_of_complex_types()
        # Set input-related endpoints to "vulnerable" that have no, or a vulnerable, linked class.
        for EP in self._endpoints.values():
            if EP.input_sanitizers:
                # E.g. linked class is annotated via @Constraint(), than assumed sane.
                # ToDo: find fields decorated by validator, not classes
                EP.vulnerable_field_names = self._sanitizer_manager.get_vulnerable_field_names(EP.input_sanitizers)
            elif EP.method_name.lower() in HttpMethods.input:
                EP.add_message(f'No associated class found for the {EP.method_name} http method.')

        # Completion
        self._messages.append(
            Message(f'{len(self._endpoints)} {self._framework_name} endpoints found.', MessageSeverity.Completion))

    def _get_endpoint_paths(self, input_names) -> set:
        paths = {finding.path.replace(self._session.input_dir, EMPTY) for finding in input_names}
        self._messages.append(
            Message(f'{len(paths)} source files added to evaluate.', MessageSeverity.Completion))
        return paths

    def _parse_for_endpoints(self, path, source_file, **kwargs):
        """
        Parse the file that contains the http methods.
        By default not vulnerable (Get, Delete), unless a RequestBody is present (Put, Post).
        """
        self._ini_endpoint()
        self._vulnerable = False
        class_name, endpoint_id = EMPTY, EMPTY
        start_method_indent = 0
        input_dir = self._session.input_dir

        for line, line_no in source_file:
            ls_line = line.lstrip(BLANK)
            current_indent = len(line) - len(ls_line)

            # Level break: After endpoint
            if current_indent <= start_method_indent and ls_line[0] == '}':
                self._create_endpoint(path, self._element)
                self._vulnerable = False

            # Class name
            class_name = get_class_name(line, class_name)

            # Remember decorators just before endpoint method
            decorator = line.lstrip()
            if decorator.startswith('@'):
                start_method_indent = len(line) - len(line.lstrip(BLANK))
                self._add_decorator(decorator)
                self._base_route = self._get_decorator_value(REQUEST_MAPPING, default=self._base_route)
                self._get_http_method(decorator)
                self._mode = METHOD

            if self._mode == METHOD:
                self._analyze_parameters(line)

            # Start of http-method, or method with parameter @Body.
            if self._http_method or BODY in line:
                self._element = Element(
                    input_dir=input_dir,
                    path=f'{input_dir}{path}',
                    line_no=line_no,
                    method_name=self._http_method,
                    class_name=class_name,
                    line=line)
                self._set_route(class_name)
                self._set_authz()
                self._http_method = EMPTY

        # Last time
        self._create_endpoint(path, self._element)

    def _analyze_parameters(self, line) -> str:
        """
        Pattern @RequestMapping:
            From the http-method parameters, get "Input sanitizer" and "vulnerable"

            Example-1 (2 params):
                "MyClass myMethod(@PathVariable("id") Long id, @Valid @RequestBody MyClass dto) {"
                    - "Input sanitizer" = first item after "@RequestBody".
                    - "vulnerable" =  "Input sanitizer" is assumed vulnerable if there is no "@Valid" decorator.

            Example-2 (3 params):
                "public String saveBasicInfoStep1(
                    @Validated(BasicInfo.class) @ModelAttribute("useraccount") UserAccount useraccount,
                    BindingResult result,
                    ModelMap model) {...}"
        Pattern @Body:
            Example-3:
                "    public MyClass myMethod(@Body final MyTargetClass myTargetInstance) {"
        """
        # Already populated
        if self._input_sanitizer:
            return EMPTY

        s = line.find('(') + 1
        if s == 0:
            return EMPTY
        e = line.rfind(')')
        if not -1 < s < e:
            return EMPTY

        # @Body mode: "http_method" is real method name
        if self._pattern == BODY and BODY in line:
            s1 = line.rfind(BLANK, 0, s)
            self._http_method = line[s1 + 1:s - 1]

        # Parameters
        params = line[s:e].split(',')
        for p in params:
            parm_items = p.split()
            # Method A - item level
            if self._pattern == REQUEST_MAPPING:
                if '@RequestBody' in parm_items:
                    self._input_sanitizer = remove_optional_type_def(
                        parm_items[parm_items.index('@RequestBody') + 1])
                    self._vulnerable = '@Valid' not in p.split()
                    break
                # Method B - Bean level
                for i in parm_items:
                    if i.startswith('@Validated'):
                        self._input_sanitizer = remove_optional_type_def(
                            self._get_text_between_parentheses(i))
                        self._vulnerable = False
                        break
            # Method C - @Body
            elif self._pattern == BODY:
                found = False
                for i in parm_items:
                    if i == BODY:
                        found = True
                    elif found:
                        if i not in AccessModifier.items and \
                                i not in NonAccessModifier.items:
                            self._input_sanitizer = remove_optional_type_def(i)
                            self._vulnerable = True
                            break

    def _get_http_method(self, decorator):
        if self._http_method:
            return
        # A. Example: "@xxxMapping"
        e = decorator.find('Mapping')
        if e > -1 and decorator[1:e].lower() in HttpMethods.all:
            self._http_method = decorator[1:e]
            return
        # B. Example: "@RequestMapping(value = "/myRoute", method = RequestMethod.POST)"
        if self._parser.find_and_set_pos('RequestMethod.', set_line=decorator):
            self._http_method = self._parser.get_next_elem()

    def _set_route(self, class_name):
        if self._pattern == REQUEST_MAPPING:
            mapping = self._get_decorator_value(f'@{self._http_method}Mapping')
            self._route = f'{self._base_route}{mapping}'
        elif self._pattern == BODY:
            self._route = class_name

    def _set_authz(self):
        authz = self._get_decorator_value('@Secured')
        if authz:
            self._authorization.add(authz)
        return

    @staticmethod
    def _get_text_between_parentheses(line) -> str:
        """
        @RequestMapping("/mybase_route"), or
        @RequestMapping(value = "/mybase_route") or
        @Secured("ROLE-1", "ROLE-2")
        """
        if not line:
            return EMPTY
        s = line.find('(') + 1
        e = line.find(')')
        for a in APOSTROPHES:
            if a in line:
                s = line.find(a, s)
                e = line.rfind(a, s, e)
                # Skip the apostrophes
                if -1 < s < e:
                    s += 1
        return line[s:e] if -1 < s < e else EMPTY

    def _get_decorator_value(self, decorator, default=EMPTY) -> str:
        value = self._get_text_between_parentheses(self._decorators.get(decorator, EMPTY))
        return value if value else default
