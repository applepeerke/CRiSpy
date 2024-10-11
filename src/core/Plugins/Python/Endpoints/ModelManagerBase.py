# ---------------------------------------------------------------------------------------------------------------------
# ModelManager# Author      : Peter Heijligers
# Description : ModelManager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-10-04 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.Framework import Framework
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import CLASS, SANITIZED_VIA_VALIDATOR
from src.core.Plugins.Enums import ContainerType
from src.core.Plugins.Functions import completion_message_of_field_analysis
from src.core.Plugins.Python.Validators.ValidatorBase import ValidatorBase
from src.gl.Enums import Output, Color, MessageSeverity
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message
from src.gl.Parse.Parser_Python import Parser_Python

PGM = 'ModelManager'


class ModelManagerBase(object):

    @property
    def messages(self):
        return self._messages

    @property
    def fields(self):
        return self._fields

    def __init__(self, framework: Framework = None, parser=None):
        self._framework = framework
        self._parser = parser if parser else Parser_Python()
        self._messages = []
        self._fields = []
        self._validator_manager = ValidatorBase()
        self._field_manager = None
        self._vulnerable_count = 0
        self._model_using_paths = []

    def find_fields(self):
        self._messages = []
        self._fields = []
        if self._framework.findings:
            self._add_fields()

    def _add_fields(self):
        self._messages.append(
            Message(f'{Color.GREEN} - {self._framework.name} attributes{Color.NC}', MessageSeverity.Completion))
        self._model_using_paths = [F.path for F in self._framework.findings if F.path is not None]

    def _find_fields(self):
        # Get implementations of Model
        # a. Get model import aliases, e.g. "models.Model" (Django) or "(Schema)" (MarshMallow)
        models = self._framework.models
        if not models:  # e.g. FastApi
            return

        # b. Find classes implementing the framework_name-model class (A)
        findings = []
        scanner = self._framework.scanner
        for model_alias in models:
            scanner.scan_dir(SearchPattern(pattern=model_alias), output=Output.Object)
            findings.extend(scanner.findings)
        findings = [F for F in findings if F.path in self._model_using_paths]

        # c. Add classes to the findings derived from (A)
        for finding in findings:
            class_name = self._get_class_name_from_line(line=finding.line)
            if class_name:
                scanner.scan_dir(SearchPattern(pattern=f'({class_name})'), output=Output.Object)
                for f in scanner.findings:
                    if self._get_class_name_from_line(line=f.line):
                        findings.append(f)

        # Process all classes
        for F in findings:
            # Get file source code
            snippet = self._parser.get_snippet(find_type=CLASS, path=F.path, line_no_start=F.line_no)
            if not snippet:
                self._error(f"Snippet not found for line no {F.line_no} in '{F.path}'")
                continue

            # Get class name from 1st line
            class_name = self._get_class_name_from_line(line=snippet[0][0])
            if not class_name:
                # self._error(f"Class not found in line {snippet[0][1]} of '{F.path}'")
                continue

            # Read snippet
            E = Element(path=F.path, name=class_name)
            total_count, vulnerable_count = 0, 0
            validated_field_names = []
            Flds = []

            for line, line_no in snippet:
                # Get field info - framework-specific.
                Fld = self._field_manager.get_field(ContainerType.Model, E, line, line_no, model_class=class_name)
                if Fld:
                    if not Fld.ID:
                        self._messages.append(
                            Message(f'*ERROR: Duplicate names will be overwritten. '
                                    f"Cause: field _as no ID at {line_no} of '{Fld.path}'. ", MessageSeverity.Error))
                    # Add field
                    Flds.append(Fld)

                # Get validator field names
                if self._validator_manager:
                    validated_field_name = self._validator_manager.get_validator_field_name(line)
                    if validated_field_name:
                        validated_field_names.append(validated_field_name)
            # Add the fields
            for Fld in Flds:
                if Fld.name in validated_field_names:
                    Fld.vulnerable = False
                    Fld.title = SANITIZED_VIA_VALIDATOR
                self._fields.append(Fld)

            total_count += len(Flds)
            vulnerable_count = sum(Fld.vulnerable is True for Fld in Flds)
            self._vulnerable_count += vulnerable_count

            # Completion message
            # N.B. Only if > 0 fields are found.
            # There may e.g. be findings like "class myClass(model.Model)" where classes are listed in comment.
            if total_count > 0:
                self._messages.append(Message(completion_message_of_field_analysis(
                    ContainerType.Model, class_name, total_count, vulnerable_count), MessageSeverity.Completion))

        if self._vulnerable_count == 0:
            self._messages.append(Message(
                f'{Color.GREEN}No{Color.NC} '
                f'vulnerable string fields found in {len(findings)} {self._framework.name} models. ',
                MessageSeverity.Completion))
        else:
            self._messages.append(Message(
                f'{self._vulnerable_count} {Color.ORANGE}possible{Color.RED} '
                f'vulnerable string fields{Color.NC} found in {len(findings)} {self._framework.name} models. ',
                MessageSeverity.Completion))

    def get_sane_fields(self) -> set:
        field_names = {F.name for F in self.fields}  # unique model field names
        return {name for name in field_names if not self._is_vulnerable(name)}

    def _is_vulnerable(self, field_name) -> bool:
        for F in self._fields:
            if F.name == field_name and F.vulnerable:
                return True
        return False

    def _get_class_name_from_line(self, line, find=CLASS):
        class_name = None
        if self._parser.find_and_set_pos(find, set_line=line, just_after=True, ignore_case=True):
            class_name = self._parser.get_next_elem(delimiters=['('], LC=False)
        return class_name

    def _error(self, message):
        self._messages.append(Message(f'{PGM}: {Color.RED}{message}{Color.NC}', MessageSeverity.Error))
        raise GeneralException(f'{PGM}: {message}')
