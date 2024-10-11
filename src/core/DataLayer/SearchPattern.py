# ---------------------------------------------------------------------------------------------------------------------
# SearchPattern.py
#
# Author      : Peter Heijligers
# Description : Search pattern
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-10-13 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.GeneralException import GeneralException
from src.gl.Validate import enforce_valid_name, toBool

EMPTY = ''


class SearchPatternAction(object):
    Investigate = 'investigate'
    Insecure = 'insecure'
    Expected = 'expected'
    FP = 'FP'


class SearchPattern(object):

    @property
    def pattern(self):
        return self._pattern

    @property
    def pattern_name(self):
        return self._pattern_name

    @property
    def status(self):
        return self._status

    @property
    def output_subfolder_name(self):
        return self._output_subfolder_name

    @property
    def category_name(self):
        return self._category_name

    @property
    def category_value(self):
        return self._category_value

    @property
    def include_comment(self):
        return self._include_comment

    @property
    def not_internet_facing(self):
        return self._not_internet_facing

    @property
    def include_if_single_thread(self):
        return self._include_if_single_thread

    @property
    def internal(self):
        return self._internal

    @property
    def apply_business_rules(self):
        return self._apply_business_rules

    @property
    def purpose(self):
        return self._purpose

    @property
    def classification(self):
        return self._classification

    @property
    def OWASP(self):
        return self._OWASP

    @property
    def search_only_for(self):
        return self._search_only_for

    @property
    def severity(self):
        return self._severity

    @property
    def remediation(self):
        return self._remediation

    @property
    def details(self):
        return self._details

    @property
    def ref_1(self):
        return self._ref_1

    @property
    def ref_2(self):
        return self._ref_2

    # Setters

    @pattern.setter
    def pattern(self, val):
        self._pattern = val

    @pattern_name.setter
    def pattern_name(self, val):
        self._pattern_name = val

    @category_name.setter
    def category_name(self, val):
        self._category_name = val

    @apply_business_rules.setter
    def apply_business_rules(self, val):
        self._apply_business_rules = val

    @search_only_for.setter
    def search_only_for(self, val):
        self._search_only_for = val

    @purpose.setter
    def purpose(self, val):
        self._purpose = val

    def __init__(self,
                 pattern,
                 pattern_name=EMPTY,
                 status=SearchPatternAction.Investigate,
                 output_subfolder_name=SearchPatternAction.Investigate,
                 category_name=EMPTY,
                 category_value=EMPTY,
                 include_comment=True,
                 not_internet_facing=EMPTY,
                 include_if_single_thread=True,
                 internal=False,
                 apply_business_rules=True,
                 purpose=EMPTY,
                 search_only_for=EMPTY,
                 OWASP=EMPTY,
                 classification=EMPTY,
                 severity=EMPTY,
                 remediation=EMPTY,
                 details=EMPTY,
                 ref_1=EMPTY,
                 ref_2=EMPTY
                 ):
        self._pattern = pattern
        if not pattern_name:
            if not pattern:
                raise GeneralException(f'{__name__} constructor: pattern is required.')
            self._pattern_name = enforce_valid_name(pattern)
        else:
            self._pattern_name = pattern_name
        self._status = status
        self._output_subfolder_name = output_subfolder_name
        self._category_name = category_name
        self._category_value = category_value
        self._include_comment = toBool(include_comment, default=True)
        self._not_internet_facing = not_internet_facing
        self._include_if_single_thread = toBool(include_if_single_thread, default=True)
        self._internal = toBool(internal, default=False)
        self._apply_business_rules = toBool(apply_business_rules, default=True)
        self._purpose = purpose
        self._search_only_for = search_only_for
        self._OWASP = OWASP
        self._classification = classification
        self._severity = severity
        self._remediation = remediation
        self._details = details
        self._ref_1 = ref_1
        self._ref_2 = ref_2
