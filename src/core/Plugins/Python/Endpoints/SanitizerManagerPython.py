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
from src.core.DataLayer.Enums import SanitizerType
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import CLASS, DEF
from src.core.Plugins.Enums import ContainerType
from src.core.Plugins.Functions import completion_message_of_field_analysis
from src.core.Plugins.Python.Frameworks.Django.DjangoParser import DjangoParser
from src.core.Plugins.SanitizerManagerBase import SanitizerManagerBase
from src.db.DataLayer.Model.Model import Model
from src.db.DataLayer.Table import Table
from src.gl.BusinessLayer.TimeManager import time_exec
from src.gl.Const import EMPTY
from src.gl.Enums import Color, MessageSeverity
from src.gl.Message import Message

model = Model()

class_dict = model.get_att_order_dict(Table.XRef_Classes, zero_based=False)
inp_dir = EMPTY


class SanitizerManagerPython(SanitizerManagerBase):

    def __init__(self):
        super().__init__()
        self._parser = DjangoParser()
        self._scanner = None
        self._parent = EMPTY
        self._fm = None
        self._XCM = None

    def add_parents(self, class_name, field_used_in_classes) -> list:
        if not self._fm:
            return []
        classes = self._fm.get_specialType_parents(class_name)
        if class_name not in classes:
            classes.append(class_name)
        if field_used_in_classes:
            for c in classes:
                if c not in field_used_in_classes:
                    field_used_in_classes.append(c)
        return classes if not field_used_in_classes else field_used_in_classes

    """
    Find Sanitizers (Serializers) and their fields
    """

    def find_fields(self, scanner):
        # Init
        self._input_dir = self._session.input_dir
        self._scanner = scanner
        self._messages = [
            Message(EMPTY, MessageSeverity.Completion),
            Message(f'{Color.GREEN} - Sanitizers{Color.NC}', MessageSeverity.Completion)
        ]
        # Get sanitizers (serializers)
        self._add_enums()
        # Parse sanitizers, evaluate and add their fields
        for S in self._sanitizers:
            if S.type != SanitizerType.Enum:
                S.fields = self._get_fields(S.element)
        # Determine sanitizers vulnerability
        self._set_sanitizer_vulnerability()
        # List all sanitizer fields (to merge with model fields)
        self._fields = [F for S in self._sanitizers for F in S.fields]
        # Set to sane by sane types defined in the project.
        self.sanitize_fields_of_complex_types()

        # Completion message
        vulnerable_count = sum(F.vulnerable for S in self._sanitizers for F in S.fields)
        if vulnerable_count == 0:
            self._messages.append(Message(
                f'{Color.GREEN}No{Color.NC} vulnerable string fields '
                f'found in {len(self._sanitizers)} sanitizers. ', MessageSeverity.Completion))
        else:
            self._messages.append(Message(
                f'{vulnerable_count} {Color.ORANGE}possible{Color.RED} vulnerable string fields{Color.NC} '
                f'found in {len(self._sanitizers)} sanitizers. ', MessageSeverity.Completion))
        self._messages.append(Message(EMPTY, MessageSeverity.Completion))

    @staticmethod
    def _is_validator_field(line) -> bool:
        return line.find('validator') > -1

    @time_exec
    def _set_sanitizer_vulnerability(self):
        # A. Analyze sanitizer vulnerability (can be serializer or model or Enum)
        count = 0
        for S in self._sanitizers:
            count += 1
            sanitizer_name = S.element.name
            vulnerable_count = sum(F.vulnerable for F in S.fields)
            # Sanitizer completion message
            self._messages.append(Message(completion_message_of_field_analysis(
                ContainerType.Serializer, sanitizer_name, len(S.fields), vulnerable_count),
                MessageSeverity.Completion))

        # B. Mark fields that are sanitizer/Enum types as vulnerable or sane.
        changed = True
        while changed:
            changed = False
            sanitizer_names = [S.name for S in self._sanitizers]
            vulnerable_sanitizer_names = [S.name for S in self._sanitizers if S.vulnerable]
            for S in self._sanitizers:
                for F in S.fields:
                    if F.field_type in sanitizer_names:
                        F.is_serializer = True
                        if F.vulnerable is False and F.field_type in vulnerable_sanitizer_names:
                            F.vulnerable = True
                            F.title = f'Possible injection. Field is a vulnerable {F.field_type} class.'
                            changed = True
                        elif F.vulnerable is True and F.field_type not in vulnerable_sanitizer_names:
                            F.vulnerable = False
                            F.title = f'Field is sanitizer {F.field_type}.'
                            changed = True

            # C. Set Sanitizers vulnerable if one of their Fields is vulnerable
            for S in self._sanitizers:
                S.vulnerable = any(F.vulnerable for F in S.fields)

    @time_exec
    def _get_sanitizer_definitions(self, sanitizer_type) -> [Element]:
        Elements = []

        # validate
        if not sanitizer_type or len(sanitizer_type) < 4:
            return Elements

        # Scan code base to get all Elements (method lines defining it).
        # (e.g. search for "(serializers.Serializer)" to find_file
        # "class OfferteInputSerializer(serializers.Serializer)"
        findings = self._scanner.scan_dir_to_findings(SearchPattern(f'({sanitizer_type})'))
        for F in findings:
            line = F.line
            self._parser.set_line(line)
            elem = self._parser.get_next_elem()
            if elem != CLASS:
                continue
            pos = self._parser.pos
            class_name = self._parser.get_next_elem(['('], LC=False)

            Elements.append(
                Element(input_dir=self._input_dir,
                        path=F.path,
                        line_no=int(F.line_no),
                        pos=pos,
                        class_name=class_name,
                        line=line
                        )
            )
        return Elements

    def _get_snippet(self, path, find_type, find_name, delimiters, line_no_start) -> list or None:
        if self._parser.find_and_set_pos(find_name, ignore_case=True):
            name_exact = self._parser.get_next_elem(delimiters, LC=False)
            if name_exact.lower() == find_name.lower():
                return self._parser.get_snippet(find_type=find_type, path=path, find_name=name_exact,
                                                delimiters=delimiters, line_no_start=line_no_start)
        return None

    @staticmethod
    def _get_mode(line, mode):
        l = line.lstrip()
        if not l:
            return mode
        if l[:4].lower() == 'def ' and '__init__' not in l:
            return DEF
        elif l[:6].lower() == 'class ':
            return CLASS
        else:
            return mode
