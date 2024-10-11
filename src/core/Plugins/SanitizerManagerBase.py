# ---------------------------------------------------------------------------------------------------------------------
# Django_source_analyzer.py
#
# Author      : Peter Heijligers
# Description : Python validation vulnerabilities
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-01-22 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.CodeBase.Sanitizer import Sanitizer
from src.core.DataLayer.Enums import SanitizerType
from src.core.Plugins.Const import SANITIZED_AT_FIELD_LEVEL, SANITIZED_BY_SANE_TYPE
from src.db.BusinessLayer.XRef.XRef_Class_manager import XRef_Class_manager
from src.db.DataLayer.Model.Model import Model, FD
from src.db.DataLayer.Table import Table
from src.gl.BusinessLayer.SessionManager import Singleton as Session

model = Model()

class_dict = model.get_att_order_dict(Table.XRef_Classes, zero_based=False)


class SanitizerManagerBase(object):

    @property
    def fields(self):
        return self._fields

    @property
    def sanitizers(self):
        return self._sanitizers

    @property
    def sane_model_charfield_names(self):
        return self._sane_model_charfield_names

    # @property
    # def all_sanitizer_names(self):
    #     return self._all_sanitizer_names

    @property
    def sane_methods(self):
        return self._sane_methods

    @property
    def messages(self):
        return self._messages

    """
    Setters
    """

    @fields.setter
    def fields(self, value):
        self._fields = value

    @sane_model_charfield_names.setter
    def sane_model_charfield_names(self, value):
        self._sane_model_charfield_names = value

    def __init__(self, min_length=40):
        self._fields = []
        self._min_length = min_length

        self._session = Session()
        self._input_dir = None
        # Properties
        self._vulnerable_parents = set()
        self._sanitizers = []
        # self._all_sanitizer_names = set()
        self._messages = []
        self._sane_model_charfield_names = set()
        self._sane_methods = {}

    def sanitize_fields_by_endpoints(self, endpoints):
        # Get all endpoint input_sanitizers (vulnerable or not)
        input_sanitizer_names = self._get_input_sanitizer_names(endpoints)
        # Check: No sanitizers, then no processing. All fields are considered input fields.
        if not input_sanitizer_names:
            return

        # Set Field "used_for_input" to False if not in an endpoint input sanitizer.
        # Set Field to "sane" if in a sane endpoint input sanitizer.
        sane_input_sanitizer_names = self._get_sane_input_sanitizer_names(endpoints)
        for F in self._fields:
            if F.parent_name not in input_sanitizer_names:
                F.used_for_input = False
                F.title = 'Field seems not to be used in endpoint input.'
                if F.parent_name in sane_input_sanitizer_names:
                    F.vulnerable = False

    def set_validators(self, parser):
        pass

    @staticmethod
    def _get_input_sanitizer_names(endpoints) -> set:
        return {sanitizer_name for EP in endpoints.values() if EP.input_sanitizers
                for sanitizer_name in EP.input_sanitizers
                } \
            if endpoints else {}

    @staticmethod
    def _get_sane_input_sanitizer_names(endpoints) -> set:
        return {sanitizer_name for EP in endpoints.values() if EP.input_sanitizers and not EP.vulnerable
                for sanitizer_name in EP.input_sanitizers
                } \
            if endpoints else {}

    def _add_enums(self):
        self._sanitizers = []
        self._sanitizers.extend(
            [Sanitizer(E, type=SanitizerType.Enum) for E in self.get_enum_definitions(self._input_dir)])

    def _get_fields(self, element: Element) -> list:
        pass

    def _set_fields_sane(self, sani_type, l, l_no: int = 0, element: Element = None, field_name=None):
        pass

    def _sanitize_field(self, F: Field, sani_type, l, l_no, field_name=None) -> bool:
        pass

    @staticmethod
    def _set_field_sane(F, l_no, title, sani_type) -> Field:
        F.title = title
        if sani_type == SANITIZED_AT_FIELD_LEVEL:
            F.title = f'{F.title} (Field is validated in a method.)'
        F.vulnerable = False
        F.element.line_no = l_no
        F.element.pos = 0
        return F

    def is_vulnerable(self, sanitizer_names):
        if not sanitizer_names:
            return False
        vulnerable_sanitizers = [S for S in self._sanitizers if S.name in sanitizer_names and S.vulnerable]
        return True if vulnerable_sanitizers else False

    def get_field_names(self) -> set:
        """ Get all field names in all sanitizers. Used in Java. """
        return {F.name for S in self._sanitizers for F in S.fields}

    def sanitize_fields_of_complex_types(self):
        """
        Field may be a complex type. Then determine field vulnerability based on the vulnerability of the complex type.
        """
        # Get sane/vulnerable type_names from all fields
        self._vulnerable_parents = {
            F.parent_name for F in self._fields if F.parent_name and F.vulnerable is True}
        sane_parents = {
            F.parent_name for F in self._fields if F.parent_name and F.parent_name not in self._vulnerable_parents}

        # Set sane
        for F in self._fields:
            if F.vulnerable and (
                    (F.parent_name and F.parent_name in sane_parents) or
                    (F.field_type and F.field_type in sane_parents)):
                F.vulnerable = False
                F.title = f"{SANITIZED_BY_SANE_TYPE} validation. Type '{F.parent_name}' is sane."

        # Set vulnerable
        for F in self._fields:
            if not F.vulnerable \
                    and F.used_for_input is True \
                    and F.field_type \
                    and F.field_type in self._vulnerable_parents:
                F.vulnerable = True
                F.title = f'Possible injection. Field is a vulnerable {F.field_type} class.'

    def get_vulnerable_field_names(self, sanitizer_names) -> set:
        """ Base used in Django and Marshmallow and derived in Java"""
        if not sanitizer_names:
            return set()
        return {F.name for sanitizer_name in sanitizer_names for F in self._fields if
                F.parent_name == sanitizer_name and
                (F.vulnerable or F.field_type in self._vulnerable_parents)
                }

    def get_enum_definitions(self, input_dir) -> [Element]:
        XCM = XRef_Class_manager(self._session.db) if self._session.db else None
        if not XCM:
            return []
        elements = [Element(input_dir=input_dir,
                            path=f'{input_dir}{row[class_dict[FD.MO_Namespace]]}{row[class_dict[FD.MO_Name]]}',
                            line_no=f'{row[class_dict[FD.CL_LineNo]]}',
                            class_name=f'{row[class_dict[FD.CL_Name]]}',
                            ) for row in XCM.get_class_names_containing_super('Enum')]
        return elements
