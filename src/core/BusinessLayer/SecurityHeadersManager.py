# ---------------------------------------------------------------------------------------------------------------------
# SecurityHeadersManager.py
#
# Author      : Peter Heijligers
# Description : Analyse globally
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-11-21 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.Enums import SecurityPattern, Purpose
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.BusinessLayer.ExtraPatternManager import ExtraPatternManager
from src.gl.Const import EMPTY
from src.gl.Enums import Output, Color, MessageSeverity
from src.core.DataLayer.SecurityHeaders import Singleton as securityHeaders
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.gl.Functions import remove_color_code
from src.gl.Message import Message

session = Session()
SH = securityHeaders()
FM = Findings_Manager()
EM = ExtraPatternManager()


class SecurityHeadersManager(object):

    @property
    def messages(self):
        return self._messages

    def __init__(self):
        self._messages = []
        self._file_type = EMPTY
        self._error_flag = False

    def start(self, scanner, file_type, language_manager=None):

        # a. Scan for security headers in the code base
        FW = language_manager.get_language(file_type)
        if FW and FW.may_have_security_headers:
            if file_type != self._file_type:
                self._file_type = file_type
                self._messages.append(Message(f"Scanning security headers for file type: '{self._file_type}'",
                                              MessageSeverity.Completion))
            scanner.scan_dir(SearchPattern('*CF_HEADER', include_comment=True), output=Output.Object)

        # b. Evaluate all found security headers (also from k8s)
        self.evaluate()

    def evaluate(self):
        """ Yield found security headers in SecurityHeader Singleton"""
        self._error_flag = False
        self._messages = []

        # a. No valid "Security headers" are found
        if all(not H.valid for H in SH.security_headers.values() if not H.optional):
            self._add_completion_message(f'No {Color.RED}Security headers{Color.NC} found that are valid.', True)
        # b. All wanted "headers" are found and valid
        elif all(H.valid for H in SH.security_headers.values() if not H.optional):
            self._add_completion_message(f'{Color.GREEN}All expected security headers are found and valid.{Color.NC}')
        # c. One or more "Security headers" found
        else:
            for header, SHR in SH.security_headers.items():
                if not SHR.found:
                    if not SHR.optional:
                        self._add_completion_message(f'No {Color.RED}{header}{Color.NC} found.', True)
                else:  # Found
                    found_values = ','.join(SHR.found_values)
                    allowed_values = ','.join(SHR.allowed_values)
                    sources = ' and '.join(SHR.search_sources)
                    if SHR.valid:
                        self._add_completion_message(f'Valid {Color.GREEN}{header}{Color.NC} found in {sources}.')
                    else:
                        self._add_completion_message(
                            f'Insecure {Color.RED}{header}{Color.NC} found in {sources}. '
                            f"Value(s) '{Color.RED}{found_values}{Color.NC}' is not one of '{allowed_values}'.", True)
        if self._messages:
            # d. Add evaluation to Findings.csv
            if self._error_flag:
                self._add_expected_finding(self._messages)

    def _add_completion_message(self, message, error=False):
        self._messages.append(Message(f'  {message}', MessageSeverity.Completion))
        if error:
            self._error_flag = True

    @staticmethod
    def _add_expected_finding(messages: [Message]):
        """ Expected but not found """
        EM.write_finding(
            search_pattern=SearchPattern(
                pattern=SecurityPattern.Security_headers),
            finding=','.join([remove_color_code(m.message) for m in messages]),
            purpose=Purpose.Expected)
