# ---------------------------------------------------------------------------------------------------------------------
# Element.py
#
# Author      : Peter Heijligers
# Description : Element in a source file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-08-01 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.Enums import SanitizerType


class Sanitizer(object):
    @property
    def element(self):
        return self._element

    @property
    def type(self):
        return self._type

    @property
    def name(self):
        return self._name

    @property
    def vulnerable(self):
        return self._vulnerable

    @property
    def fields(self):
        return self._fields

    # Setters
    @vulnerable.setter
    def vulnerable(self, value):
        self._vulnerable = value

    @fields.setter
    def fields(self, value):
        self._fields = value
        self._evaluate_vulnerable()

    def __init__(self, element: Element = None, fields=None, type=SanitizerType.Serializer):
        self._element = element
        self._type = type
        self._name = self._element.class_name if element else None  # redundant
        self._fields = fields or []
        self._vulnerable = False
        self._evaluate_vulnerable()

    def _evaluate_vulnerable(self):
        self._vulnerable = any(F.vulnerable for F in self._fields)
