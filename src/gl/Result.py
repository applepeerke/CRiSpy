from src.gl.Const import EMPTY
from src.gl.Enums import ResultCode, MessageSeverity

SEVERITY_ERROR = ('error', 'exception', 'sqlexception')
SEVERITY_WARNING = ('warning', 'cancel')
SEVERITY_INFO = ('info', 'ok', 'completion')

MNEMONIC = {
    MessageSeverity.Error: 'E ',
    MessageSeverity.Completion: 'C ',
    MessageSeverity.Warning: 'W ',
    MessageSeverity.Info: 'I '
}


class Result(object):
    """
    result_value = Key-Value list (e.g. ["myComp", "MYCOMP"]
    text = Key-Value description (e.g. "MYCOMP (mycomp)")
    """

    @property
    def OK(self):
        return self._code in (ResultCode.Ok, ResultCode.Equal)

    @property
    def WA(self):
        return self._code in (ResultCode.Warning, ResultCode.NotFound)

    @property
    def ER(self):
        return self._code in (ResultCode.Error, ResultCode.Cancel)

    @property
    def code(self):
        return self._code

    @property
    def text(self):
        return self._text

    @property
    def result_value(self):
        return self._value

    @property
    def severity(self):
        return self._severity

    @property
    def messages(self):
        return self._messages

    @text.setter
    def text(self, value):
        self._text = value

    @result_value.setter
    def result_value(self, value):
        self._value = value

    @code.setter
    def code(self, value):
        self._code = value
        self._severity = self._code_to_severity(value)

    @severity.setter
    def severity(self, value):
        self._severity = value
        self._code = self.severity_to_code(value)

    @messages.setter
    def messages(self, value):
        self._messages = value

    def __init__(self, code=ResultCode.Ok, text=EMPTY, severity: MessageSeverity = None, messages=None):
        self._code = code
        self._text = text
        self._value = EMPTY
        self._severity = severity
        self._messages = messages or []
        self._messages_raw = set()
        if severity:
            self._code = self.severity_to_code(severity)
        else:
            self._severity = self._code_to_severity(code)

    def add_message(self, message, severity=MessageSeverity.Info):
        """
        Result.text is treated as a completion/error message.
        All messages are added to Result.messages.
        """
        mnemonic = MNEMONIC.get(severity)
        p_mnemonic = MNEMONIC[self._code_to_severity(self._code)]
        p_completion_message = self._text
        if severity in (MessageSeverity.Error, MessageSeverity.Warning, MessageSeverity.Completion):
            # Keep only 1st high-level message
            if self.code == ResultCode.Ok:
                self._text = message
            # Set This code and severity
            self._code = self.severity_to_code(severity)
            self._severity = self._code_to_severity(self._code)
        # Move old completion text to messages.
        if p_completion_message and p_completion_message != self._text:
            self._add_unique_message(p_completion_message, p_mnemonic)
        # Add the new message
        self._add_unique_message(message, mnemonic)

    def _add_unique_message(self, message, mnemonic):
        if message and message not in self._messages_raw:
            self._messages.append(f'{mnemonic}{message}')
            self._messages_raw.add(self._text)

    def get_text(self, max_lines=20, sophisticate=True) -> str:
        """
        sophisticate: self._text is considered a completion message.
        messages may start with mnemonic ("C ", "E ", "I " or "W" ).
        """
        if not self._messages or max_lines < 1:
            return self._text
        suffix = '\n...' if len(self._messages) > max_lines else EMPTY
        sophisticate = False if not self._text else sophisticate

        # Concatenate the messages
        message = EMPTY
        for i in range(min(len(self._messages), max_lines)):
            m = self._messages[i]
            # Remove other Completion messages (optional)
            if sophisticate and len(m) > 2 and m[:2] == MNEMONIC[MessageSeverity.Completion]:
                continue
            # Remove mnemonic (optional)
            if sophisticate and len(m) > 2 and m[:2] in MNEMONIC.values():
                m = m[2:]
            if not self._text or self._text not in m:
                message = f'{message}\n{m}' if message else m
        return f'{self._text}\n{message}{suffix}' if self._text else f'{message}{suffix}'

    def severity_to_code(self, severity: MessageSeverity) -> str:
        if severity == MessageSeverity.Error:
            return ResultCode.Error
        elif severity == MessageSeverity.Warning:
            return ResultCode.Warning if self._code != ResultCode.Error else self._code
        elif severity in (MessageSeverity.Info, MessageSeverity.Completion):
            return ResultCode.Ok if self._code not in (ResultCode.Error, ResultCode.Warning) else self._code
        else:
            raise ValueError(f"{__name__}: Severity '{severity}' can not be mapped to Result.")

    @staticmethod
    def _code_to_severity(code) -> MessageSeverity:
        if code == ResultCode.Error:
            return MessageSeverity.Error
        elif code in (ResultCode.Warning, ResultCode.Cancel, ResultCode.NotFound):
            return MessageSeverity.Warning
        elif code in (ResultCode.Ok, ResultCode.Equal):
            return MessageSeverity.Info
        else:
            raise ValueError(f"{__name__}: Severity '{code}' can not be mapped to Result.")
