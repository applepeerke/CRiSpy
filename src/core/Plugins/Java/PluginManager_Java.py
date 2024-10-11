# ---------------------------------------------------------------------------------------------------------------------
# PluginManager_K8s.py
#
# Author      : Peter Heijligers
# Description : Java
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-09-16 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import FrameworkName, SecurityTopic
from src.core.Plugins.Const import CONFIGURED, IMPLEMENTED, VALUE
from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.core.Plugins.Functions import find_filename_from_parent_dir, bullet
from src.core.Plugins.Java.Endpoints.EndpointManagerJava import EndpointManagerJava
from src.core.Plugins.Java.Frameworks.Spring.SpringModelManager import SpringModelManager
from src.core.Plugins.Python.Frameworks.Django.AuthenticationManager import AuthenticationManager
from src.gl.Const import EMPTY
from src.gl.Enums import Color, MessageSeverity
from src.utils.XmlPom2Dict import XmlPom2Dict

# Topics
SUMMARY_SPRING = {
    SecurityTopic.Authentication: {CONFIGURED: False, IMPLEMENTED: False},
    SecurityTopic.Authorization: {CONFIGURED: False, IMPLEMENTED: False},
    SecurityTopic.Session: {CONFIGURED: False, IMPLEMENTED: False, VALUE: EMPTY},
    SecurityTopic.Validation: {CONFIGURED: False, IMPLEMENTED: False}
}

COLOURED_NOT = f'{Color.RED}NOT{Color.NC} '

# Config
SPRING_CONFIG_SECURITY = 'spring-boot-starter-security'
SPRING_CONFIG_VALIDATION = 'spring-boot-starter-validation'

# Implementation
AUTHENTICATION_CLASSES = ['AuthenticationManagerBuilder', 'AuthenticationManagerResolver']
AUTHORIZATION_CLASSES = ['EnableGlobalMethodSecurity', 'EnableMethodSecurity']
SESSION_CLASSES = ['SessionCreationPolicy']
AUTH_CONDITIONAL_CLASSES = ['HttpSecurity', 'EnableWebSecurity', 'SecurityFilterChain']

# Informational (bullets)
SPRING_SECURITY_IMPLEMENTATION = {
    'AuthenticationManagerBuilder': 'Helper for AuthenticationManagerResolver',
    'AuthenticationManagerResolver': 'Resolves to an AuthenticationManager per context',
    'EnableGlobalMethodSecurity': 'Functional interface to Spring Method Security (authorization)',
    'EnableMethodSecurity': 'Functional interface to Spring Method Security (authorization) '
                            '(fine-grained version of EnableGlobalMethodSecurity)',
    'HttpSecurity': 'Base support for authentication and authorization',
    'EnableWebSecurity': 'Enables base HttpSecurity, SecurityFilterChain and basic authentication',
    'SessionCreationPolicy': 'Creates httpSession (NEVER, ALWAYS, STATELESS, IF_REQUIRED)',
    'SecurityFilterChain': 'Class that configures the security logic',
    'UsernamePasswordAuthenticationFilter': 'Basic authentication',
    'Secured': 'Spring Method Security. Endpoint authorization via roles. Defined in EnableGlobalMethodSecurity',
    'RolesAllowed': 'Spring Method Security. Endpoint authorization via roles. Defined in EnableGlobalMethodSecurity',
    'PreAuthorize': 'Spring Method Security. Endpoint authorization via roles. Defined in EnableGlobalMethodSecurity',
    'PostAuthorize': 'Spring Method Security. Endpoint authorization via roles. Defined in EnableGlobalMethodSecurity',
    'springSecurity': 'Test class',
}


def add_desc(implementation):
    return f'{implementation} {Color.GREEN}({SPRING_SECURITY_IMPLEMENTATION.get(implementation, EMPTY)}){Color.NC}'


class PlugInManager_Java(FrameworkPluginBase):
    @property
    def config_artifacts(self):
        return self._config_artifacts

    def __init__(self, scanner):
        super().__init__(scanner)
        self._framework_name = FrameworkName.Spring
        self._endpoint_manager = EndpointManagerJava(self._framework_name, self._scanner)
        self._config_groups = []  # <groupId>
        self._config_artifacts = []  # <artifactId>
        self._config_items = {}

    def run(self, frameworks=None, method_code=None):
        """ method_code is for unit test only """
        super().run(frameworks, method_code)
        self._summary()

    def _summary(self):
        self._messages = []
        # Set Configuration flags
        SUMMARY_SPRING[SecurityTopic.Authentication][CONFIGURED] = \
            any(i in self._topic_imports for i in AUTHENTICATION_CLASSES)
        SUMMARY_SPRING[SecurityTopic.Session][CONFIGURED] = 'SessionCreationPolicy' in self._topic_imports

        # Set Implementation flags
        for i in AUTH_CONDITIONAL_CLASSES:
            if i not in self._topic_imports:
                self._add_message(f'Expected class {Color.GREEN}{i}{Color.NC} has {COLOURED_NOT}been found.')

        SUMMARY_SPRING[SecurityTopic.Authentication][IMPLEMENTED] = \
            any(i in self._topic_imports for i in AUTHENTICATION_CLASSES)
        SUMMARY_SPRING[SecurityTopic.Authorization][IMPLEMENTED] = \
            any(i in self._topic_imports for i in AUTHORIZATION_CLASSES)
        SUMMARY_SPRING[SecurityTopic.Session][IMPLEMENTED] = 'SessionCreationPolicy' in self._topic_imports

        # Output
        for topic, values in SUMMARY_SPRING.items():
            config_not = EMPTY if values[CONFIGURED] else COLOURED_NOT
            implemented_not = EMPTY if values[IMPLEMENTED] else COLOURED_NOT
            AND = 'and' if values[CONFIGURED] == values[IMPLEMENTED] else 'but'
            value = f'{Color.BLUE} Value is {Color.NC}{values[VALUE]}.' if values.get(VALUE, EMPTY) else EMPTY
            self._add_message(
                f'{topic}'
                f'{Color.BLUE} has been {config_not}{Color.NC}configured'
                f'{Color.BLUE} {AND} {implemented_not}{Color.NC}implemented.{value}')

        self._plugin_log_result('Summary')

    def configuration(self):
        """ Spring WebSecurityConfiguration"""
        if not self._frameworks.get(FrameworkName.Spring):
            return

        paths = find_filename_from_parent_dir('pom.xml')
        if not paths:
            return

        [self._add_config(path) for path in paths]

        # Implementation: Find security imports
        findings = self._scan_for_import(
            'org.springframework.security',
            SecurityTopic.Configuration,
            use_filter=False)
        self._topic_imports = {self._get_implementation_from_import(f) for f in findings}
        security_implementation = [add_desc(i) for i in self._topic_imports if i]
        security_implementation_text = f'{bullet()}'.join(security_implementation)
        self._add_message(f'{Color.BLUE}Security implementation used:{Color.NC}'
                          f'{bullet()}{security_implementation_text}')
        # Output
        self._plugin_log_result(SecurityTopic.Configuration)

    def authentication(self):
        if not self._frameworks.get(FrameworkName.Spring):
            return

        # Configuration
        self._topic = SecurityTopic.Security
        self._list_config('org.springframework.security', first=True)
        self._list_config(SPRING_CONFIG_SECURITY, last=True)

        # - Summary
        SUMMARY_SPRING[SecurityTopic.Authentication][CONFIGURED] = \
            self._config_items[self._topic][SPRING_CONFIG_SECURITY]
        SUMMARY_SPRING[SecurityTopic.Authorization][CONFIGURED] = \
            self._config_items[self._topic][SPRING_CONFIG_SECURITY]

        # Implementation
        if self._config_items.get(self._topic):
            self._scan_for_import('SecurityFilterChain', 'Authentication and/or authorization')
            self._scan_for_import('WebSecurityCustomizer', 'Authentication and/or authorization relaxation')
            self._topic_message(color_if_not_found=Color.GREEN)

        # Endpoints
        authc = AuthenticationManager()
        authc.authentication_endpoints(FrameworkName.Spring, self._endpoint_manager.endpoints)
        self._messages.extend(authc.messages)

        self._plugin_log_result(SecurityTopic.Authentication)

    def _add_config(self, path):
        """ Find security in the pom.xml dependencies.
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-config</artifactId>
        </dependency>
        or:
        https://www.baeldung.com/spring-enablewebsecurity-vs-enableglobalmethodsecurity
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        """
        xml_parser = XmlPom2Dict()
        parent_tree = ['<dependencies>', '<dependency>']
        self._config_groups = xml_parser.get_texts(path, parent_tree=parent_tree, tag='<groupId>')
        self._config_artifacts = xml_parser.get_texts(path, parent_tree=parent_tree, tag='<artifactId>')

    """
    Endpoint
    """

    def _endpoint_analysis(self, title=EMPTY):
        self._messages = []  # output
        self._title = title
        self._framework_names = []

        framework = self._frameworks.get(FrameworkName.Spring)
        if not framework:
            return

        self._framework_names.append(framework.name)

        # Preparation
        # a. Find fields
        model_manager = SpringModelManager()
        model_manager.find_fields()
        self._fields = model_manager.fields
        self._messages = model_manager.messages

        # b. Sanitize fields
        SM = self._endpoint_manager.sanitizer_manager
        SM.fields = self._fields

        # c. Input validation configuration and implementation
        #   1. Has endpoint input validation been configured?
        self._topic = SecurityTopic.Validation
        self._list_config(SPRING_CONFIG_VALIDATION, first=True, last=True)

        #   2. Implementation - Scan for "@Valid" and "@Validated"
        findings = self._scan('@Valid')
        #   3. Summary
        SUMMARY_SPRING[SecurityTopic.Validation][CONFIGURED] = self._config_items[self._topic][SPRING_CONFIG_VALIDATION]
        SUMMARY_SPRING[SecurityTopic.Validation][IMPLEMENTED] = len(findings) > 0

        # d. Framework-related analysis
        self._endpoint_analysis_framework()

        # e. Now it is known if fields are used for endpoint input.
        SM.sanitize_fields_of_complex_types()

    def session(self):
        # - Summary
        pattern = 'SessionCreationPolicy'
        findings = self._scan(f'{pattern}.')  # Include dot
        for F in findings:
            s = F.line.find(pattern) + len(pattern) + 1
            for delim in (')', ' ', ',', '}'):
                e = F.line.find(delim, s)
                if e > -1:
                    break
            state = F.line[s:] if e == -1 else F.line[s:e]
            SUMMARY_SPRING[SecurityTopic.Session][VALUE] = state

    """
    General
    """

    def _list_config(self, item, first=False, last=False):
        # Init
        if first:
            self._config_items[self._topic] = {}

        # Add {item: True/False}
        self._config_items[self._topic][item] = \
            item in self._config_artifacts or \
            item in self._config_groups

        # Completion
        if last:
            text = f'has {COLOURED_NOT}been configured in' if not self._config_items.get(self._topic) else 'in'
            message = f'{Color.BLUE}{self._topic.title()} {text}{Color.NC} pom.xml: '
            for item, configured in self._config_items[self._topic].items():
                text = f' has {COLOURED_NOT}been configured.' if not configured else EMPTY
                message = f'{message}{bullet()}{item}{text}'
            self._add_message(f'{message}\n', MessageSeverity.Completion)
