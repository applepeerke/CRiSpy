# ---------------------------------------------------------------------------------------------------------------------
# ExtraPatternManager.py
#
# Author      : Peter Heijligers
# Description : Maintain ExpectedPatterns (patterns which may not be present)
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-01-13 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.SearchPatternManager import SearchPatternManager
from src.core.DataLayer.Finding import Finding
from src.core.DataLayer import FindingTemplate
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.DataLayer.Enums import Severity, SecurityPattern, Purpose
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.gl.GeneralException import GeneralException

PGM = 'ExtraPatternManager'
CODE = 'code'
PURPOSE = 'purpose'

extra_patterns = {
    # Expected
    SecurityPattern.Vulnerable_endpoint: {CODE: 'request', PURPOSE: Purpose.Expected},
    SecurityPattern.Security_headers: {CODE: 'header', PURPOSE: Purpose.Expected},
    SecurityPattern.Request: {CODE: 'request', PURPOSE: Purpose.Expected},
    SecurityPattern.Header: {CODE: 'header', PURPOSE: Purpose.Expected},
    SecurityPattern.Authentication: {CODE: 'authenticat', PURPOSE: Purpose.Expected},
    SecurityPattern.Session: {CODE: 'authenticat', PURPOSE: Purpose.Expected},
    SecurityPattern.Cookie: {CODE: 'cookie', PURPOSE: Purpose.Expected},
    SecurityPattern.Token: {CODE: 'token', PURPOSE: Purpose.Expected},
    SecurityPattern.CSRF: {CODE: 'csrf', PURPOSE: Purpose.Expected},
    SecurityPattern.Authorisation: {CODE: 'authori', PURPOSE: Purpose.Expected},
    SecurityPattern.Validation: {CODE: 'security', PURPOSE: Purpose.Expected},
    SecurityPattern.ErrorHandling: {CODE: 'logger', PURPOSE: Purpose.Expected},
    SecurityPattern.Logger: {CODE: 'logger', PURPOSE: Purpose.Expected},
    SecurityPattern.Encoding: {CODE: 'encoding', PURPOSE: Purpose.Expected},
    # Additional
    SecurityPattern.Config: {CODE: 'configuration', PURPOSE: Purpose.Additional},
}

SPM = SearchPatternManager()
FM = Findings_Manager()


class ExtraPatternManager(object):
    def __init__(self):
        self._patterns = []

    """
    This class is for patterns expected to exist but not found in the code base.
    They are reported in Findings.csv.
    """

    @staticmethod
    def get_pattern(pattern_name, purpose=None, severity=Severity.Medium) -> SearchPattern or None:
        """ get SearchPattern object. Add it to the table if it does not exist yet. """
        if not purpose:
            for k, v in extra_patterns.items():
                if v.get(CODE) == pattern_name:
                    purpose = v.get(PURPOSE)
        if not purpose:
            GeneralException(f"{__name__}: Unknown purpose for pattern '{pattern_name}'")
        default = SearchPattern(
            pattern=pattern_name, pattern_name=pattern_name, category_name=purpose, severity=severity)
        SP = SPM.copy_valid_pattern(
            pattern_name, pattern_name, default=default, category_name=purpose, purpose=purpose)
        return SP

    @staticmethod
    def write_findings(findings: [Finding]):
        """ Write Finding objects to Findings.txt for the same search pattern (precondition)"""
        sps = set()
        if not findings:
            return
        FM.initialize(FindingTemplate.FINDINGS)
        for finding in findings:
            sps.add(finding.search_pattern)
            # Add finding
            FM.add_finding(finding)
        if len(sps) != 1:
            GeneralException(f'{__name__}: 1 search pattern expected, {len(sps)} found.')
        # Write findings to Findings.csv
        FM.write_findings(sp=sps.pop())

    @staticmethod
    def write_finding(search_pattern, finding: str, purpose):
        FM.initialize(FindingTemplate.FINDINGS)
        search_pattern.category_name = purpose
        search_pattern.purpose = purpose
        # Add finding
        FM.add_finding(Finding(finding=finding, search_pattern=search_pattern))
        # Write finding to Findings.csv
        FM.write_findings(sp=search_pattern)
