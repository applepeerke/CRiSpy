# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_AWS.py
#
# Author      : Peter Heijligers
# Description : JavaScript plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-07-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os
from abc import ABC

from src.core.BusinessLayer.ExtraPatternManager import ExtraPatternManager
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.Enums import FrameworkName, SecurityTopic, SecurityPattern, Purpose, ConfigFileType
from src.core.DataLayer.Finding import Finding
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.AWS.Config.ConfigBaseManager import ConfigBaseManager
from src.core.Plugins.AWS.Config.ConfigParser import ConfigParser
from src.core.Plugins.AWS.Config.JsonConfigToCsv import JsonConfigToCsv
from src.core.Plugins.AWS.Config.JsonManager import JsonManager
from src.core.Plugins.AWS.Config.YamlConfigToCsv import YamlConfigToCsv
from src.core.Plugins.AWS.Config.YamlManager import YamlManager
from src.core.Plugins.AWS.Constants import ALLOW, DENY
from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Const import EMPTY, CSV_EXT
from src.gl.Enums import Color, Language, MessageSeverity
from src.gl.Functions import remove_color_code
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message
from src.gl.Validate import normalize_dir

PGM = 'PluginManager_AWS'

csvm = CsvManager()
FM = Findings_Manager()
EM = ExtraPatternManager()
JsonParser = JsonConfigToCsv()
YamlParser = YamlConfigToCsv()


class PlugInManager_AWS(FrameworkPluginBase, ABC):

    def __init__(self, scanner):
        super().__init__(scanner)
        self._config_managers = {}
        self._framework_name = FrameworkName.AWS

    def configuration(self):
        """
        Find and parse configuration files
        Write corresponding results to csv (without analysis, this follows in analyze_policies)
        List corresponding managers
        """
        self._messages = []
        self._config_managers = {}

        framework = self._frameworks.get(FrameworkName.AWS)
        if not framework:
            return

        self._parse_config(JsonParser, ConfigFileType.Json)
        self._parse_config(YamlParser, ConfigFileType.Yaml)

        self._plugin_log_result(SecurityTopic.Configuration)

    def _parse_config(self, parser: ConfigParser, file_type: ConfigFileType):
        # Scan input dir on config files (yaml, json), and convert them to a standard csv format.
        self._messages.extend(parser.run())
        config_path = parser.get_output_file(file_type)
        # Keep the csv-rows in a new config manager.
        if os.path.isfile(config_path):
            CM = self._get_config_manager(file_type)
            CM.rows = csvm.get_rows(include_header_row=True, data_path=config_path)
            self._config_managers[file_type] = CM

    @staticmethod
    def _get_config_manager(file_type: ConfigFileType) -> ConfigBaseManager:
        if file_type == ConfigFileType.Yaml:
            return YamlManager()
        elif file_type == ConfigFileType.Json:
            return JsonManager()
        else:
            raise GeneralException(f"{__name__}: Not supported config file '{file_type}'.")

    def _endpoint_analysis(self):
        self._messages = []
        # Analyze paths
        for file_type, ConfigM in self._config_managers.items():
            self._messages = []
            data_dir = normalize_dir(f'{self._session.log_dir}DataFlow', create=True)
            ConfigM.endpoint_analysis()
            # Output
            self._endpoint_analysis_output_AWS(file_type, data_dir, ConfigM.endpoints, ConfigM.fields)

    def authentication(self):
        self._messages = []
        # Analyze "Allow" policies
        self._analyze_policies()
        self._plugin_log_result(SecurityTopic.Authentication)

    def _analyze_policies(self):
        findings = []
        for _, CM in self._config_managers.items():
            CM.analyze_policy_effect(ALLOW)
            findings.extend(CM.findings)
            CM.analyze_policy_effect(DENY)
            findings.extend(CM.findings)
            self._messages.extend(CM.messages)
        EM.write_findings(findings)

    def _endpoint_analysis_output(self):
        pass

    def _endpoint_analysis_output_AWS(
            self, file_type: ConfigFileType, data_dir, endpoints: [Endpoint], fields: [Field]):
        # Report the endpoints found
        f_file_type = f'{Color.BLUE}{file_type}{Color.NC}'
        suffix = ':' if endpoints else '.'
        self._messages.append(Message(
            f'{Color.ORANGE}{len(endpoints)} {f_file_type} {Color.GREEN}endpoints found{suffix}{Color.NC}',
            MessageSeverity.Completion))
        for EP in endpoints:
            self._messages.append(
                Message(f' {Color.GREEN}- {Color.NC}'
                        f'{EP.element.name} {Color.GREEN}with method {Color.NC}'
                        f'{EP.element.method_name}', MessageSeverity.Completion))

        input_count = sum(F.used_for_input is True for F in fields)
        self._messages.append(
            Message(' ', MessageSeverity.Completion))  # ako new line
        self._messages.append(
            Message(f'{Color.ORANGE}{len(fields)} {f_file_type} {Color.GREEN}fields found. ',
                    MessageSeverity.Completion))
        self._messages.append(
            Message(f'{Color.ORANGE}{input_count}{Color.GREEN} are used for input.{Color.NC}',
                    MessageSeverity.Completion))
        if not fields:
            return

        # a. Write field input validations to Excel
        FM.initialize(FindingTemplate.MODEL_FIELD_VALIDATIONS)
        FM.write_results(
            fields, FindingTemplate.MODEL_FIELD_VALIDATIONS,
            data_path=f'{data_dir}{FindingTemplate.MODEL_FIELD_VALIDATIONS}{CSV_EXT}',
            base_dir=self._session.input_dir
        )

        # b. Write messages to Excel and stdout
        FM.initialize(FindingTemplate.MODEL_WARNINGS)
        FM.write_results(
            self._messages, FindingTemplate.MODEL_WARNINGS,
            data_path=f'{data_dir}{FindingTemplate.MODEL_WARNINGS}{CSV_EXT}')

        # c. Write Field vulnerability to Findings.csv and stdout
        FM.initialize(FindingTemplate.FINDINGS)
        sp = SearchPattern(
            pattern=SecurityPattern.Vulnerable_endpoint,
            category_name=Language.General,
            category_value=EMPTY,
            purpose=Purpose.Expected
        )
        finding_written = False
        vulnerable_fields = [F for F in fields if F.vulnerable]
        for F in vulnerable_fields:
            status = f'{Color.RED}vulnerable{Color.NC}'
            finding = (f'{Color.BLUE}Field{Color.NC} '
                       f'{F.element.name} '
                       f'{Color.BLUE}in object{Color.NC} {F.parent_name} '
                       f'{Color.BLUE}is{Color.NC} {status}. ')
            # Add the additional finding.
            FM.add_finding(
                Finding(
                    search_pattern=sp,
                    path=F.element.path,
                    line_no=F.element.line_no,
                    start_pos=0,
                    line=F.element.line,
                    finding=remove_color_code(finding),
                    base_dir=self._session.input_dir
                ),
            )
            self._messages.append(Message(finding))
            finding_written = True

        # d. Write the additional findings to Findings.txt (of type expected)
        if vulnerable_fields:
            FM.write_findings(sp=sp)
            self._add_completion_message_AWS([F.element.name for F in vulnerable_fields])
            finding_written = True

        if not finding_written:
            self._messages.append(Message(f'{Color.GREEN}No vulnerable fields found.{Color.NC}',
                                          MessageSeverity.Completion))

    def _add_completion_message_AWS(self, vulnerable_fields):
        self._messages.append(Message(
            f'{Color.ORANGE}Injection warning.{Color.NC} '
            f'{Color.BLUE}Vulnerable fields: {Color.ORANGE}{set(vulnerable_fields)}{Color.NC}',
            MessageSeverity.Completion))
