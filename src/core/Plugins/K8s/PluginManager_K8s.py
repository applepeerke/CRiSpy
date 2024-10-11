# ---------------------------------------------------------------------------------------------------------------------
# PluginManager_K8s.py
#
# Author      : Peter Heijligers
# Description : Manage k8s configuration
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-09-16 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from abc import ABC
from typing import Optional

from src.core.BusinessLayer.SecurityHeadersManager import SecurityHeadersManager
from src.core.DataLayer.Enums import FrameworkName, SecurityTopic
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.DataLayer.SecurityHeaders import Singleton as securityHeaders
from src.core.Plugins.FrameworkPluginBase import FrameworkPluginBase
from src.core.Plugins.K8s.Functions import get_k8s_dir, sanitize
from src.gl.Const import BLANK, EMPTY
from src.gl.Enums import Color, MessageSeverity
from src.gl.Functions import strip_crlf

SINGLE_VALUE = 'SINGLE_VALUE'
ANY_OF = 'ANY_OF'
NOT = 'NOT'
MORE_SET_HEADERS = 'more_set_headers'
MODE_INGRESS = 'ingress'
YAML = 'values.yaml'
prefix = f'  {Color.GREEN}{YAML.title()}{Color.NC} '
expected_mode_block_name_values = {
    'database': {'sslmode': [ANY_OF, 'require']},
    'elasticsearch': {'ssl': [ANY_OF, 'true']},
    'logging': {'level': [ANY_OF, 'warning', 'error']},
    'raise_exceptions': {SINGLE_VALUE: [ANY_OF, 'false']},
    'allowed_hosts': {SINGLE_VALUE: [NOT, '["*"]']},
}

Headers = securityHeaders()
SHM = SecurityHeadersManager()


class PluginManager_K8s(FrameworkPluginBase, ABC):

    def __init__(self, scanner):
        super().__init__(scanner)
        self._mode = EMPTY
        self._block_name = EMPTY
        self._more_set_headers = set()
        self._framework_name = FrameworkName.K8s

    def configuration(self):
        dir_name = get_k8s_dir(self._session.input_dir)
        if not dir_name:
            return

        framework = self._frameworks.get(FrameworkName.K8s)
        if not framework:
            return

        scanner = framework.scanner
        scanner.initialize_scan()
        findings = scanner.scan_dir_to_findings(
            SearchPattern('more_set_headers'),
            dir_name,
            file_type='yaml'
        )
        if not findings:
            return

        paths = {F.path for F in findings}
        for path in paths:
            with open(path) as file:
                [self._process_line(line, MODE_INGRESS) for line in file]

        # Store the headers
        Headers.set_headers_from_k8s(self._more_set_headers)
        # Yield the headers
        SHM.evaluate()
        self._messages = SHM.messages

        self._plugin_log_result(SecurityTopic.Configuration)

    def authentication(self):
        pass

    def _endpoint_analysis(self):
        pass

    def _process_line(self, line, mode=None):
        """
        Example-1 Single-line: allowed_hosts: ["*"] /*  mode=allowed_hosts, block_type=SINGLE_VALUE, value=["*"] */
        Example-2 Block:       elasticsearch:       /*  mode=elasticsearch, block_type=ssl, value=true */
                                ssl: true
        """
        p = line.find(':')
        # New mode
        if not line.startswith(BLANK) and p > -1:
            self._mode = line[:p]
        if self._mode == MODE_INGRESS or mode == MODE_INGRESS:
            self._get_more_set_headers(line)
        else:
            self._evaluate_value(self._get_value_and_set_block_name(line, p))

    def _get_value_and_set_block_name(self, line, p) -> Optional[str]:
        """ p is on ':' """
        if -1 < p < len(line) + 1:
            self._block_name = SINGLE_VALUE
        else:
            self._block_name = self._mode
        line = strip_crlf(line[p + 1:].strip())
        return line.lower() if line else EMPTY

    def _evaluate_value(self, value):
        if not value:
            return
        expected_block_name_values = expected_mode_block_name_values.get(self._mode)
        if expected_block_name_values:
            self._evaluate_condition(value, expected_block_name_values.get(self._block_name))

    def _evaluate_condition(self, value, expected_values):
        if not expected_values:
            return
        block_name_text = f' for {self._block_name}' if self._block_name != SINGLE_VALUE else EMPTY
        if (expected_values[0] == ANY_OF and value not in expected_values) or \
                (expected_values[0] == NOT and value in expected_values):
            self._add_message(f'{prefix}{self._mode}: '
                              f'{Color.ORANGE}{value}{Color.NC} '
                              f'{Color.RED}is not allowed{Color.NC}'
                              f'{block_name_text}.', MessageSeverity.Error)

    def _get_more_set_headers(self, line):
        p = line.find(MORE_SET_HEADERS)
        s = p + len(MORE_SET_HEADERS)
        if p > -1 and s < len(line):
            self._more_set_headers.add(sanitize(line[s:]))
