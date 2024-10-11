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
from src.core.Plugins.Const import SANITIZED_BY_ID
from src.gl.Const import EMPTY
from src.gl.BusinessLayer.SessionManager import Singleton as Session

session = Session()


class Field(object):
    def __init__(self, context_type=None, element: Element = None, parent_name=None, vulnerable=True,
                 title=None, field_type=None, length=0, model_class=None, is_sanitizer=False, used_for_input=False,
                 decorators=None):
        """
        Meta information on a Django db.model or Serializer field.
        :param context_type: Serializer or Model oor Config
        :param element: Element type, defines exact position in the code
        :param parent_name: Class or method name where it is in.
        :param vulnerable:
        :param title: Reason why it is sanitized or vulnerable.
        :param field_type: CharField, PhoneNumber etc.
        :param length: Length attribute.
        :param model_class: Model class associated with serializer field
        :param is_sanitizer: Is the field_type a sanitizer (Serializer or Enum) class itself?
        :param used_for_input: Is it used for input?
        :param decorators: list of decorators or None.
        """

        self._context_type = context_type
        self._element = element
        self._parent_name = parent_name
        self._vulnerable = vulnerable
        self._title = title
        self._field_type = field_type
        self._length = length
        self._model_class = model_class

        self._name = element.name  # redundant
        self._contains_id = False

        # Set to True if input field, otherwise it is unknown at this stage.
        self._used_for_input = used_for_input if used_for_input is True else EMPTY
        self._decorators = decorators or []

        # Derived ID to support duplicates
        # (N.B. in UT session.input_dir may be None)
        if self._element.path:
            current_dir = self._element.path.replace(session.input_dir, EMPTY) \
                if session.input_dir else self._element.path
            self._ID = f'{self._element.name}|{current_dir}|{self._element.line_no}' \
                if self._element else None

        self._ID_logical = None
        self._set_ID_logical(model_class)
        self._set_contains_id(element)
        self._is_serializer = is_sanitizer

    @property
    def name(self):
        return self._name

    @property
    def context_type(self):
        return self._context_type

    @property
    def element(self):
        return self._element

    @property
    def parent_name(self):
        return self._parent_name

    @property
    def vulnerable(self):
        return self._vulnerable

    @property
    def title(self):
        return self._title

    @property
    def field_type(self):
        return self._field_type

    @property
    def length(self):
        return self._length

    @property
    def ID(self):
        return self._ID

    @property
    def ID_logical(self):
        return self._ID_logical

    @property
    def contains_id(self):
        return self._contains_id

    @property
    def model_class(self):
        return self._model_class

    @property
    def used_for_input(self):
        return self._used_for_input

    @property
    def decorators(self):
        return self._decorators

    @property
    def is_serializer(self):
        return self._is_serializer

    # Setters
    @ID_logical.setter
    def ID_logical(self, value):
        self._ID_logical = value

    @vulnerable.setter
    def vulnerable(self, value):
        self._vulnerable = value

    @title.setter
    def title(self, value):
        self._title = value

    @length.setter
    def length(self, value):
        self._length = value

    @model_class.setter
    def model_class(self, value):
        self._set_ID_logical(value)
        self._model_class = value

    @used_for_input.setter
    def used_for_input(self, value):
        self._used_for_input = value

    @is_serializer.setter
    def is_serializer(self, value):
        self._is_serializer = value

    def _set_ID_logical(self, model_class):
        if model_class and self._element:
            self._ID_logical = f'{model_class}.{self._element.name}'
        elif self._parent_name:
            self._ID_logical = f'{self._parent_name}.{self._element.name}'

    def _set_contains_id(self, E):
        if E and E.name:
            name_lower = E.name.lower()
            if name_lower in ('id', 'identifier') \
                    or name_lower.endswith('_id') \
                    or name_lower.startswith('id_') \
                    or E.name.endswith('Id') \
                    or E.name.endswith('ID'):
                self._contains_id = True
                self._vulnerable = False
                self._title = f'{SANITIZED_BY_ID}.'
