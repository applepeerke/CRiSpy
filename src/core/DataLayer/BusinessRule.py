# ---------------------------------------------------------------------------------------------------------------------
# BusinessRule.py
#
# Author      : Peter Heijligers
# Description : DBDriver attribute
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-18 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

EMPTY = ''


class RuleOperator(object):
    And = 'And'
    Or = 'Or'
    Contains = 'Contains'
    ContainsNot = 'ContainsNot'
    Empty = EMPTY
    StartsWith = 'StartsWith'


class BusinessRule(object):

    @property
    def pattern_name(self):
        return self._pattern_name

    @pattern_name.setter
    def pattern_name(self, val):
        self._pattern_name = val

    @property
    def file_name(self):
        return self._file_name

    @file_name.setter
    def file_name(self, val):
        self._file_name = val

    @property
    def file_ext(self):
        return self._file_ext

    @file_ext.setter
    def file_ext(self, val):
        self._file_ext = val

    @property
    def search_value(self):
        return self._search_value

    @search_value.setter
    def search_value(self, val):
        self._search_value = val

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, val):
        self._offset = val

    @property
    def rule_seq(self):
        return self._rule_seq

    @rule_seq.setter
    def rule_seq(self, val):
        self._rule_seq = val

    @property
    def rule_operator(self):
        return self._rule_operator

    @rule_operator.setter
    def rule_operator(self, val):
        self._rule_operator = val

    @property
    def finding_status(self):
        return self._finding_status

    @finding_status.setter
    def finding_status(self, val):
        self._finding_status = val

    @property
    def function_name(self):
        return self._function_name

    @function_name.setter
    def function_name(self, val):
        self._function_name = val

    @property
    def function_parm_names(self):
        return self._function_parm_names

    @function_parm_names.setter
    def function_parm_names(self, val):
        self._function_parm_names = val

    @property
    def function_parm_values(self):
        return self._function_parm_values

    @function_parm_values.setter
    def function_parm_values(self, val):
        self._function_parm_values = val

    def __init__(self,
                 pattern_name,
                 file_name=None,
                 file_ext=None,
                 search_value=None,
                 rule_seq=0,
                 rule_operator=RuleOperator.Empty,
                 finding_status='Investigate',
                 function_name=None,
                 function_parm_names=None,
                 function_parm_values=None
                 ):

        self._pattern_name = pattern_name
        self._file_name = file_name
        self._file_ext = file_ext
        self._search_value = search_value
        self._rule_seq = rule_seq
        self._rule_operator = rule_operator
        self._finding_status = finding_status
        self._function_name = function_name
        self._function_parm_names = function_parm_names
        self._function_parm_values = function_parm_values
        # offset is a derived value
        self._offset = str.find(search_value.lower(), pattern_name.lower())
