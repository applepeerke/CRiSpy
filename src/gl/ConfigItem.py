class ConfigItem(object):

    @property
    def label(self):
        return self._label

    @property
    def value(self):
        return self._value

    @property
    def validate_type(self):
        return self._validate_type

    def __init__(self, label, value, validate_type=None):
        self._label = label
        self._value = value
        self._validate_type = validate_type
