# ---------------------------------------------------------------------------------------------------------------------
# Sourcefile_Manager_Python.py
#
# Author      : Peter Heijligers
# Description : Build a call x-ref from a source file.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.Enums import SecurityTopic, SecurityPattern, Purpose
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Enums import ContainerType
from src.core.Plugins.Functions import bullet
from src.core.Plugins.PluginBase import PluginBase
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.Finding import Finding
from src.core.Plugins.Python.DataFlow.ClassManager import ClassManager
from src.gl.BusinessLayer.LogManager import STRIPE
from src.gl.Enums import Color, MessageSeverity, Language, Output
from src.gl.Functions import remove_color_code
from src.gl.Const import EMPTY, CSV_EXT, NONE
from src.gl.Message import Message
from src.gl.Validate import normalize_dir

class_manager = ClassManager()
FM = Findings_Manager()
# ToDo: Other languages
sp = SearchPattern(
    pattern=SecurityPattern.Vulnerable_endpoint,
    category_name=Language.Python,
    category_value=EMPTY,
    purpose=Purpose.Expected
)

CONFIG = 'CONFIG'
ENDPOINTS = 'ENDPOINTS'
AUTHENTICATION = 'AUTHENTICATION'
SESSION = 'SESSION'


class FrameworkPluginBase(PluginBase):

    @property
    def endpoint_manager(self):  # UT only
        return self._endpoint_manager

    def __init__(self, scanner):
        super().__init__(scanner)
        self._endpoint_manager = None
        self._framework_names = []
        self._endpoints = {}
        self._fields = []
        self._output_dir = normalize_dir(f'{self._session.log_dir}DataFlow', create=True)
        self._title = EMPTY
        self._topic_imports = set()  # Used in Java an C#
        self._topic = EMPTY
        self._topics_found = {}

    def run(self, frameworks=None, method_code=None):
        """ method_code is for unit test only """
        self._frameworks = frameworks

        if not method_code or method_code == CONFIG:
            self.configuration()
        if not method_code or method_code == ENDPOINTS:
            self.endpoint_analysis()
        if not method_code or method_code == AUTHENTICATION:
            self.authentication()
        if not method_code or method_code == SESSION:
            self.session()

        self._not_implemented()

    def configuration(self):
        pass

    def endpoint_analysis(self):
        self._endpoint_analysis()
        self._endpoint_analysis_output()
        self._plugin_log_result(SecurityTopic.Endpoint_analysis)

    def authentication(self):
        pass

    def authorization(self):
        pass

    def session(self):
        pass

    def _endpoint_analysis(self):
        raise NotImplementedError

    def _endpoint_analysis_framework(self):
        """ Analysis for a framework (multiple frameworks may be analyzed consecutively) """
        if not self._endpoint_manager:
            return
        # a. Analysis
        self._endpoint_manager.frameworks = self._frameworks
        self._endpoint_manager.endpoint_analysis()
        self._sanitizer_manager = self._endpoint_manager.sanitizer_manager

        # b. Set fields "used_for_input"
        self._set_fields_used_for_input()

        # c. Multiple frameworks are possible
        self._append_fields()
        self._append_endpoints()
        self._messages.extend(self._endpoint_manager.messages)
        self._plugin_log_result(SecurityTopic.Endpoint_analysis)

    def _append_fields(self):
        ids = [f.ID for f in self._fields]
        for f in self._endpoint_manager.fields:
            if f.ID not in ids:
                self._fields.append(f)

    def _append_endpoints(self):
        """
        returns { Endpoint.ID: Endpoint, [vulnerable_field_names] }
        """
        # Add new endpoints
        for EP in self._endpoint_manager.endpoints.values():
            if EP.ID not in self._endpoints:
                self._endpoints[EP.ID] = EP

        # FastAPI skips sanitizer manager processing, so set the fields here.
        if not self._sanitizer_manager.fields and self._fields:
            self._sanitizer_manager.fields = self._fields

        # Add vulnerable field names (e.g. Marshmallow after Django; MM has no endpoints)
        for EP in self._endpoints.values():
            vulnerable_field_names = self._sanitizer_manager.get_vulnerable_field_names(EP.input_sanitizers)
            [self._endpoints[EP.ID].vulnerable_field_names.add(field_name) for field_name in vulnerable_field_names]
        return

    def _set_fields_used_for_input(self):
        """
        Set "used_for_input" to
        A. True:
            1. Field is in a Model (Django, SQLAlchemy)
            2. Field is used in an Input serializer (e.g. calling ".is_valid(")
        B. False:
            3. Field is not used in an endpoint
        """
        for F in self._fields:
            if F.context_type in ContainerType.used_for_input:
                F.used_for_input = True
            else:
                # Set Maximum usage (PROCESSED, RETURNED) of class and descendants.
                # a. Add descendant class names
                parent_name = F.parent_name
                parents = class_manager.add_descendants(
                    parent_name, exclude_start_with=['serializers.'])
                # b. Add "parent" class names (this serializer may be a "field" in another serializer)
                parents = self._sanitizer_manager.add_parents(parent_name, parents)
                F.used_for_input = self._endpoint_manager.get_endpoint_input_parent_usage(parents)

        # b. Evaluate field "used_for_input" and vulnerability via endpoints
        self._sanitizer_manager.sanitize_fields_by_endpoints(self._endpoint_manager.endpoints)

    def _endpoint_analysis_output(self):
        """
        Multiple frameworks supported.
        a. Endpoints.csv - Endpoints vulnerability
        b. MIFV - Missing Input Field Validation
        c. Warnings.txt
        d. Findings.txt - vulnerable_endpoints

        """
        if not self._framework_names:
            return

        # a. Write Endpoints - also vulnerability
        self._endpoint_manager.write_endpoints(self._endpoints)

        # b. Write field input validations to Excel
        FM.initialize(FindingTemplate.MODEL_FIELD_VALIDATIONS)
        FM.write_results(
            self._fields, FindingTemplate.MODEL_FIELD_VALIDATIONS,
            data_path=f'{self._output_dir}{FindingTemplate.MODEL_FIELD_VALIDATIONS}{self._title}{CSV_EXT}',
            base_dir=self._session.input_dir
        )

        # c. Write warnings to Excel and stdout
        FM.initialize(FindingTemplate.MODEL_WARNINGS)
        FM.write_results(
            self._messages, FindingTemplate.MODEL_WARNINGS,
            data_path=f'{self._output_dir}{FindingTemplate.MODEL_WARNINGS}{self._title}{CSV_EXT}')

        # d. Add Endpoint vulnerability (of type expected) to memory
        FM.initialize(FindingTemplate.FINDINGS)

        finding_written = False
        for EP in self._endpoints.values():
            method_name = EP.method_name or EP.element.name
            parent_clause = f'{Color.BLUE}route{Color.NC} {EP.route} ' if EP.route else \
                f'{Color.BLUE}class{Color.NC} {EP.element.class_name} '

            status = f'{Color.BLUE}is{Color.NC} {Color.GREEN}sane.{Color.NC}'
            if EP.vulnerable:
                status = f'{Color.BLUE}is{Color.NC} {Color.RED}vulnerable.{Color.NC}'
            elif method_name.lower() == 'get':
                status = f'{status} {Color.BLUE}{method_name} method is considered sane.{Color.NC}'
            elif EP.input_sanitizers and EP.vulnerable_usage:
                status = f'{status} but {Color.ORANGE}sanitizer may be bypassed.{Color.NC}'
            elif not EP.input_sanitizers:
                status = f'{Color.BLUE}may be{Color.NC} {Color.ORANGE}vulnerable{Color.NC}{Color.GREEN}: ' \
                         f'No input sanitizer found.{Color.NC}'

            details = f"{Color.BLUE}Linked to class {Color.NC}{', '.join(list(EP.input_sanitizers))}." \
                if EP.input_sanitizers else EMPTY
            details = f"{details} {', '.join(m.message for m in EP.messages)}"

            finding_text = (f'{Color.BLUE}Endpoint{Color.NC} '
                            f"{EP.element.path.replace(self._session.input_dir, '../')} "
                            f'{parent_clause}'
                            f'{Color.BLUE}method{Color.NC} {method_name} '
                            f'{status} {details}')

            # If vulnerable or error, add to Findings.txt too.
            self._add_findings(EP, finding_text)
            finding_written = True

            self._messages.append(Message(finding_text, MessageSeverity.Error))

        # d. Write extra findings (of type expected) to Findings.csv
        FM.write_findings(sp=sp)

        # e. If vulnerable endpoint, write summary message to std_out
        vulnerable_endpoints = [EP for EP in self._endpoints.values() if EP.input_sanitizers and EP.vulnerable]
        new_line = '\n'
        for EP in vulnerable_endpoints:
            finding_written = True
            vulnerable_fields = self._endpoint_manager.sanitizer_manager.get_vulnerable_field_names(
                EP.input_sanitizers) \
                if self._endpoint_manager and self._endpoint_manager.sanitizer_manager else set()
            # Get vulnerable parameter_flows,
            vulnerable_PFs = [PF for PF in EP.parameter_flows if PF.vulnerable]
            if not vulnerable_PFs:
                if vulnerable_fields:
                    p = f'{new_line}{Color.ORANGE}Injection warning.{Color.NC} '
                    self._add_completion_message(p, EMPTY, EP, vulnerable_fields)
            else:
                for PF in vulnerable_PFs:
                    prefixes = []
                    if PF.db_mutation:
                        prefixes.append(f'{Color.RED}Stored XSS.{Color.NC} ')
                    if PF.returned_outputs:
                        prefixes.append(f'{Color.RED}Reflected XSS.{Color.NC} ')
                    if not prefixes:
                        p = f'{new_line}{Color.ORANGE}Injection warning.{Color.NC} '
                        self._add_completion_message(p, PF, EP, vulnerable_fields)
                    else:
                        prefixes[0] = f'{new_line}{prefixes[0]}'
                        [self._add_completion_message(p, PF, EP, vulnerable_fields) for p in prefixes]
            new_line = EMPTY

        if not finding_written:
            self._messages.append(
                Message(f'{Color.GREEN}No Endpoint findings found to report.{Color.NC}', MessageSeverity.Completion))

    def _add_findings(self, EP: Endpoint, finding):
        if not EP.vulnerable:
            return
        # a. Vulnerable fields
        # ToDo

        # One message in Findings.txt (text of the finding is in Warnings.txt)
        if not finding:
            finding = ', '.join([remove_color_code(m.message) for m in EP.messages
                                 if m.severity >= MessageSeverity.Error])
        if finding:
            self._add_finding(EP, remove_color_code(finding))

    def _add_finding(self, EP: Endpoint, finding):
        FM.add_finding(
            Finding(
                path=EP.element.path,
                line_no=EP.element.line_no,
                start_pos=0,
                line=EP.element.line,
                finding=finding,
                search_pattern=sp,
                base_dir=self._session.input_dir
            ),
        )

    def _add_completion_message(self, title, PF, EP, vulnerable_fields):
        status = f'{Color.RED}vulnerable{Color.NC}' if EP.vulnerable else f'{Color.GREEN}sane{Color.NC}'
        endpoint = f' {EP.route}' if EP.route \
            else f' {EP.element.class_name}.{EP.element.name}' if EP.element.name \
            else EMPTY
        method_name = f' {Color.BLUE}method{Color.NC} {EP.method_name}' if EP.method_name else EMPTY
        classes = ', '.join(list(EP.input_sanitizers)) if EP.input_sanitizers else NONE
        if EP.vulnerable:
            fields_clause = f' {Color.BLUE}fields {Color.ORANGE}{vulnerable_fields}{Color.NC}' \
                if vulnerable_fields else EMPTY
        else:
            fields_clause = f' {Color.BLUE}is {Color.GREEN}sane{Color.NC}'
        parameter = f' {Color.BLUE}parameter{Color.NC} {PF.input_parameter}' if PF else EMPTY
        message = f'{title}' \
                  f'{Color.BLUE}Endpoint{Color.NC}{endpoint}{method_name}{parameter} ' \
                  f'{Color.BLUE}is linked to class {Color.NC} ' \
                  f'{classes} {status}{fields_clause}' \
                  f'{Color.BLUE}. Module is{Color.NC} ' \
                  f"{EP.element.path.replace(self._session.input_dir, '../')} "
        self._messages.append(Message(message, MessageSeverity.Completion))

    def _scan_for_imports(self, import_path):
        findings = self._scan_for_import(
            import_path,
            self._topic,
            use_filter=False)
        impl = {self._get_implementation_from_import(f) for f in findings}
        for i in impl:
            self._topic_imports.add(i)

    def _scan_for_import(self, pattern, topic, use_filter=True) -> [Finding]:
        """
        Scan while optionally temporarily toggle of filtering.
        Add a result message.
        """
        # Scan
        findings = self._scan(pattern, use_filter)
        if topic not in self._topics_found:
            self._topics_found[topic] = {}
        self._topics_found[topic][pattern] = findings
        return findings

    def _topic_message(self, list_filenames=True, color_if_not_found=Color.RED):
        """
        Message: "<topic> <pattern> has been found."
        If no pattern has been found in the topic: "No <topic> patterns have been found."
        """
        [self._add_topic_pattern_message(pattern, findings, list_filenames)
         for pattern, findings in self._topics_found[self._topic].items() if findings]
        # No pattern found
        if not any(findings for pattern, findings in self._topics_found[self._topic].items()):
            self._add_message(
                f'{Color.BLUE}{self._topic} patterns have {color_if_not_found}NOT{Color.NC} been found{Color.NC}')

    def _add_topic_pattern_message(self, pattern, findings, list_filenames):
        filenames_text = EMPTY
        if list_filenames:
            filenames = f"{bullet()}".join({f'{f.file_name}' for f in findings})
            filenames_text = f'{Color.BLUE} in {Color.NC}{bullet()}{Color.NC}{filenames}\n'
        self._add_message(
            f'{Color.BLUE}{self._topic} pattern{Color.NC} {pattern} '
            f'{Color.BLUE}has been found{Color.NC}{filenames_text}',
            MessageSeverity.Info)

    @staticmethod
    def _get_implementation_from_import(f: Finding) -> str:
        line = f.line.strip()
        if not line:
            return EMPTY
        p = line.rfind('.')
        if p == -1:
            return EMPTY
        return line[p + 1:-1] if line.endswith(';') else line[p + 1:]

    def _scan(self, pattern, use_filter=True) -> [Finding]:
        if not use_filter:
            self._scanner.initialize_scan(use_filter=False)
        self._scanner.scan_dir(SearchPattern(pattern), output=Output.Object)
        findings = self._scanner.findings
        if not use_filter:
            self._scanner.initialize_scan(use_filter=True)
        return findings

    def _add_message(self, message, severity=MessageSeverity.Info):
        if not self._messages:
            self._messages.append(Message(f'{Color.GREEN}{STRIPE}{Color.NC}', MessageSeverity.Completion))
        self._messages.append(Message(message, severity))
