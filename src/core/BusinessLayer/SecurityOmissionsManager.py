# ---------------------------------------------------------------------------------------------------------------------
# SecurityOmissionsManagerger.py
#
# Author      : Peter Heijligers
# Description : Analyse globally
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-11-21 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.ExtraPatternManager import ExtraPatternManager, extra_patterns, CODE, PURPOSE
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.BusinessLayer.ProgramLanguageManager import ProgramLanguageManager
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.Enums import SecurityPattern
from src.core.DataLayer.SearchPattern import SearchPattern
from src.gl.Enums import Output, Color, Language, MessageSeverity, ApplicationTypeEnum
from src.gl.Functions import remove_color_code, is_internet_facing
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message

PGM = 'SecurityOmissionsManager'
LM = ProgramLanguageManager()
FM = Findings_Manager()
EM = ExtraPatternManager()


class SecurityOmissionsManager(object):

    @property
    def messages(self):
        return self._messages

    def __init__(self, scanner):
        self._scanner = scanner
        self._messages = []
        self._file_type = None
        self._language = None

    def start(self, project_type: ApplicationTypeEnum, file_type='py'):
        self._language = Language.Python
        FM.initialize(FindingTemplate.FINDINGS)
        """
        Purpose: not being found may be a finding too!
        """
        if file_type != self._file_type:
            self._file_type = file_type
            self._messages.append(Message(f"Scanning security patterns for file type: '{self._file_type}'",
                                          MessageSeverity.Completion))
        """
        Authentication
        """
        self.scan(SecurityPattern.Authentication, ['authe', ' AuthZ('])  # AuthZ import also
        if is_internet_facing(project_type):
            self.scan(SecurityPattern.Session, ['session'])
            #  - Are cookies used?
            self.scan(SecurityPattern.Cookie, ['cookie'])
            #  - Is CSRF protection present?
            self.scan(SecurityPattern.CSRF, ['csrf'])
        #  - Are tokens used?
        self.scan(SecurityPattern.Token, ['token', 'JWT'])

        """
        Authorisation
        """
        self.scan(SecurityPattern.Authorisation, ['authori', 'authz'])
        """
        Validation /sanitizing / encoding
        """
        self.scan(SecurityPattern.Validation, ['validat', 'saniti'])
        if is_internet_facing(project_type):
            self.scan(SecurityPattern.Encoding, ['autoescape'])

        """
        Error handling
        """
        if file_type == 'py':
            self.scan(SecurityPattern.ErrorHandling, [' except ', ' excpt '])
        else:
            self.scan(SecurityPattern.ErrorHandling, ['catch '])

        """
        Logging
        """
        self.scan(SecurityPattern.Logger, [' _log', 'logger '])

        if len(self._messages) <= 1:
            self._messages.append(Message(f'  {Color.GREEN}All{Color.NC} main security patterns are found '
                                          f'{Color.GREEN}(auth, authz, validation, error handling, logging).{Color.NC}',
                                          MessageSeverity.Completion))

    def scan(self, security_pattern: SecurityPattern, patterns, include_comment=False):
        # Consistency check
        sp_pattern = extra_patterns.get(security_pattern)
        if not sp_pattern:
            raise GeneralException(f"{PGM}: Pattern '{security_pattern}' has not been defined as 'extra pattern'.")
        # Scan
        for pattern in patterns:
            self._scanner.scan_dir(SearchPattern(pattern, include_comment=include_comment), output=Output.Object)
            if len(self._scanner.findings) > 0:
                break
        # Result
        if len(self._scanner.findings) == 0:
            # Detail
            message = f'No {Color.RED}{security_pattern}{Color.NC} pattern found.'
            EM.write_finding(
                search_pattern=SearchPattern(pattern=sp_pattern.get(CODE)),
                finding=remove_color_code(message),
                purpose=sp_pattern.get(PURPOSE))
            self._messages.append(Message(f'  {message}', MessageSeverity.Error))
