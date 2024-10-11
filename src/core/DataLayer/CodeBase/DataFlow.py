# ---------------------------------------------------------------------------------------------------------------------
# Endpoint.py
#
# Author      : Peter Heijligers
# Description : Parameter in a source file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-03-29 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase import Element
from src.gl.Const import PYTHON_BUILT_INS


class DataFlow(object):

    @property
    def tainted_values(self):
        return self._tainted_values

    @property
    def elements(self):
        return self._elements

    def __init__(self, elements: [Element]):
        self._elements = elements
        self._tainted_values = set([E.value for E in elements])

    def add_tainted(self, E):
        if E and E.value not in PYTHON_BUILT_INS:
            self.elements.append(E)
            self._tainted_values.add(E.value)
