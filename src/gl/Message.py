from src.gl.Const import EMPTY
from src.gl.Enums import MessageSeverity


class Message( object ):

    @property
    def message(self):
        return self._message

    @property
    def severity(self):
        return self._severity

    def __init__(self, message=EMPTY, severity: MessageSeverity = MessageSeverity.Info):
        self._message = message
        self._severity = severity
