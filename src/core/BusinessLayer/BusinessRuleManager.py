# ---------------------------------------------------------------------------------------------------------------------
# BusinessRuleManager.py
#
# Author      : Peter Heijligers
# Description : Manage business rules data
#
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.core.DataLayer.BusinessRule import *
from src.core.DataLayer.CoreModel import ImportFiles
from src.gl.BusinessLayer.CsvManager import CsvManager as Csv_Manager

PGM = 'BusinessRuleManager'
csvManager = Csv_Manager()
csvManager.file_name = ImportFiles.BusinessRules
business_rules = []
business_rules_populated = False
line = EMPTY


class BusinessRuleManager(object):
    """
    Manage business rules
    """

    @property
    def business_rules(self):
        return business_rules

    @property
    def error_message(self):
        return self._error_message

    def __init__(self):
        self._error_message = None

    def exclude(self, source_line, pattern_name, pos=-1, file_ext=None, file_name=None):
        global business_rules, business_rules_populated, line
        # Populate business rules (if needed)
        if not business_rules_populated:
            business_rules_populated = True
            self.populate_business_rules()

        # Validate input
        if source_line == EMPTY:
            self._error_message = '{} Source line is required.'.format(PGM)
        if pattern_name == EMPTY:
            self._error_message = '{} Pattern name is required.'.format(PGM)
        if pos == -1:
            self._error_message = '{} Position is required.'.format(PGM)

        # No business rules defined: Nothing to exclude.
        if len(business_rules) == 0 or self._error_message:
            return False

        """
        Find business rules that exclude a special value. Example:
        
        Pattern File Ext Oper SearchValue Status
        ------- ---- --- ---- ----------- ------
        hash                  hashmap     FP
        """

        line = source_line.lower()

        # As soon as the excluding value is found, return exclude(True) = FP
        for br in business_rules:

            # If pattern is specified, it must match
            if br.pattern_name != pattern_name and br.pattern_name != '*':
                continue

            # If extension is specified, it must match
            if br.file_ext and file_ext is not None and file_ext[1:] not in br.file_ext.split(','):
                continue

            # If file name is specified, it must match
            if br.file_name and file_name is not None and br.file_name != file_name.lower():
                continue

            # Check BR.

            # Ignore the finding when br-value...
            if br.search_value:
                # ... contains the pattern?
                if not br.rule_operator \
                        and self._isPartOfPatternToExclude(br, pos):
                    return True

                # ... is start of the line?
                if br.rule_operator == RuleOperator.StartsWith \
                        and str(line).lstrip().startswith(br.search_value):
                    return True

                # ... is part of the line?
                if br.rule_operator == RuleOperator.Contains \
                        and br.search_value in line:
                    return True
                # ... does not exist in the line?
                if br.rule_operator == RuleOperator.ContainsNot \
                        and str(br.search_value) not in line:
                    return True
            else:
                # No search value and no expression specified: Always a FP (e.g. comment )
                if not br.rule_operator:
                    return True

        # No excludes found: nothing to exclude.
        return False

    @staticmethod
    def _isPartOfPatternToExclude(br, pos) -> bool:
        global line

        if br.offset == -1:
            start_pos = pos
        else:
            start_pos = pos - br.offset

        find_pos = str.find(line, br.search_value, start_pos)

        if find_pos > -1 and find_pos - start_pos < 2:  # if pattern starts with a blank, the difference = 1, else 0.
            return True
        else:
            return False

    @staticmethod
    def populate_business_rules():
        """
        Populate BusinessRules from csv file rows.
        """
        global business_rules

        csvManager.file_name = f'{ImportFiles.BusinessRules}.csv'
        rows = csvManager.get_rows(include_empty_row=False)
        for row in rows:
            business_rules.append(
                BusinessRule(
                    row[0],
                    file_name=row[1],
                    file_ext=row[2],
                    rule_seq=row[3],
                    search_value=row[4],
                    rule_operator=row[5],
                    finding_status=row[6],
                )
            )
