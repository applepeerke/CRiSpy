from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Sanitizer import Sanitizer
from src.core.DataLayer.Enums import SanitizerType
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Java.Functions import get_decorator_name
from src.core.Plugins.SanitizerManagerBase import SanitizerManagerBase
from src.gl.Const import BLANK, EMPTY, ALL
from src.gl.Enums import Output

CONSTRAINT = '@Constraint'
VALIDATORS = 'Validators'
SANITIZERS = 'Sanitizers'


class SpringSanitizerManager(SanitizerManagerBase):

    @property
    def validators(self):
        return self._validators

    def __init__(self, scanner):
        super().__init__()
        self._scanner = scanner
        self._decorators = {}
        self._validators = {}
        self._parser = None

    def set_validators(self, parser):
        """
        a. Find validators = methods annotated by "@Constraint".
        b. Find sanitizers = methods annotated by "@{validator}".
        """
        self._parser = parser
        # a. Find constraints
        self._scanner.scan_dir(SearchPattern(CONSTRAINT), output=Output.Object)

        # b. Get validators (parse from source)
        snippets = {F.path: self._parser.get_snippet(find_type=ALL, path=F.path) for F in self._scanner.findings}
        # Parse endpoints to validators
        for path, source_file in snippets.items():
            self._parse(path, source_file, VALIDATORS)

        # c. Set sanitizers from validators
        # ToDo: bug: find the FIELDS decorated by validator, not the classes
        for validator in self._validators:
            self._scanner.scan_dir(SearchPattern(f'@{validator}'), output=Output.Object)
            snippets = {F.path: self._parser.get_snippet(find_type=ALL, path=F.path) for F in self._scanner.findings}
            # Parse endpoints
            for path, source_file in snippets.items():
                self._parse(path, source_file, SANITIZERS)

    def _parse(self, path, source_file, processor):
        """
        Example:
            @Constraint(validatedBy = {my1stValidator.class, my2ndValidator.class})
            public @interface myValidator {
                ...
                }
        """
        start_method_indent = 0
        mode = EMPTY

        for line, line_no in source_file:
            ls_line = line.lstrip(BLANK)
            current_indent = len(line) - len(ls_line)

            # Level break: After method
            if current_indent <= start_method_indent and ls_line[0] == '}':
                mode = EMPTY
                self._decorators = {}

            # Remember decorators just before method (of endpoint/constructor)
            line_lstripped = line.lstrip()
            if line_lstripped.startswith('@'):
                mode = 'decorator'
                start_method_indent = len(line) - len(line.lstrip(BLANK))
                self._decorators[get_decorator_name(line_lstripped)] = line_lstripped
            # After decorators
            elif mode == 'decorator':
                mode = 'found'

            if mode == 'found':
                mode = EMPTY
                if processor == VALIDATORS and CONSTRAINT in self._decorators:
                    self._add_validator(path, line, line_no)
                elif processor == SANITIZERS:
                    self._add_sanitizer(path, line, line_no)

    def _add_validator(self, path, line, line_no):
        validator_name = self._get_class_name(line)
        # Start of http-method, or method with parameter @Body.
        if validator_name:
            self._validators[validator_name] = self._get_element(path, validator_name, line, line_no)

    def _add_sanitizer(self, path, line, line_no):
        sanitizer_name = self._get_class_name(line)
        if sanitizer_name:
            self._sanitizers.append(
                Sanitizer(self._get_element(path, sanitizer_name, line, line_no), type=SanitizerType.Validator))

    def _get_element(self, path, class_name, line_no, line) -> Element:
        return Element(
            input_dir=self._session.input_dir,
            path=f'{self._session.input_dir}{path}',
            line_no=line_no,
            class_name=class_name,
            line=line)

    def _get_class_name(self, line) -> str:
        self._parser.find_and_set_pos('{', set_line=line, just_before=True)
        return self._parser.get_prv_elem(LC=False)
