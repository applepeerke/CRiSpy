# ---------------------------------------------------------------------------------------------------------------------
# ExpressionManager.py
#
# Author      : Peter Heijligers
# Description : Define and evaluate expressions
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-05 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.gl.Const import EMPTY
from src.gl.GeneralException import GeneralException

PGM = 'ExpressionManager'

CONTAINS = 'contains'
CONTAINS_NOT = 'contains_not'
functions = (CONTAINS, CONTAINS_NOT)
required_parameters = {
    CONTAINS: 1,
    CONTAINS_NOT: 1
}
line = EMPTY
AND = 'and'
OR = 'or'
relations = (AND, OR)


class ExpressionManager(object):
    """
    Manage expressions
    """

    @property
    def index(self):
        return self._index

    def __init__(self):
        self._index = -1

    def evaluate(self, pattern, parms: list, source_line) -> int:
        """
        :param pattern:
        :param parms: 1st parameter is the condition (function name).
            2nd optional parameter is relation (and/or) for next parameters.
        :param source_line:
        :return: index of first found word in source_line. Or -1 if none found.
        """
        global line
        self._index = -1
        """
        Example: verify(contains, and, ssl, false)
        """
        # Validate input
        if not pattern:
            raise GeneralException(f'{PGM} Input error: Pattern is required.')
        if not parms or not source_line:
            return -1

        line = source_line.lower()

        # First check if pattern is in the line.
        if pattern not in line:
            return -1

        function = parms[0]
        if function not in required_parameters:
            raise GeneralException(f"{PGM} Input error: Function '{function}' is not supported.")

        parms = parms[1:] if len(parms) > 0 else []
        if len(parms) < required_parameters[function]:
            raise GeneralException(f'{PGM} Input error: Too few required parameters specified '
                                   f"for function '{function}'.")
        self.__getattribute__(f'_{function}')(parms)  # _contains or _contains_not
        return self._index

    def _contains(self, parms) -> bool:
        """
        It is a finding if it contains the word(s).
        Example:
            search_pattern = *CF_VERIFY(contains, or, false, none)
            (meaning: "verify" assignment should not contain "false" or "none")
            line = " verify_sll = FALSE"
                returns: index=14, i.e. This is a finding.
        """
        relation, find_words = self._split_parms(parms)
        if relation == AND:
            found = all(w in line for w in find_words)
        elif relation == OR:
            found = any(w in line for w in find_words)
        else:
            raise NotImplementedError

        if found:
            self._set_index(find_words)
        return found

    def _contains_not(self, parms):
        """
        It is a finding if it does NOT contain the word(s)
        Example:
            search_pattern = *CF_VERIFY(contains_not, or, true, all)
            (meaning: "verify"-line does not contain "true" or "all")
            line = " verify_sll = FALSE"
                returns: index=0, i.e. This is a finding (but no index can be retrieved).
        """
        # Word(s) are not found, then it is a finding.
        if self._contains(parms) is False:
            self._index = 0

    @staticmethod
    def _split_parms(parms) -> (str, list):
        relation = parms[0] if parms[0] in relations else EMPTY
        if not relation and len(parms) > 1:
            raise GeneralException(
                f"{PGM} Input error: In case of multiple parameters the 1st parameter of function 'contains' must be "
                f'a relation ({relations})')

        find_words = parms if not relation else parms[1:]
        if relation and len(find_words) < 2:
            raise GeneralException(
                f"{PGM} Input error: 1st parameter of function 'contains' is a relation ({relations}) "
                f'but there are too few parameters following to relate to')
        return relation, find_words

    def _set_index(self, find_words):
        for w in find_words:
            self._index = line.find(w)
            if self._index > -1:
                return
        raise GeneralException(
            f'{PGM}.set_index: Something went wrong. A match was found but the index can not be retrieved.')
