# ---------------------------------------------------------------------------------------------------------------------
# Author      : Peter Heijligers
# Description : ModelManager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-11-02 PHe First creation
# ---------- --- ------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.Scanner import Scanner
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.Enums import FrameworkName
from src.core.DataLayer.Framework import Framework
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Const import SANITIZED_VIA_VALIDATOR, SANITIZED_BY_TYPE
from src.core.Plugins.Enums import ContainerType
from src.core.Plugins.Functions import completion_message_of_field_analysis
from src.core.Plugins.Java.Enums import AccessModifier
from src.core.Plugins.Java.Functions import remove_optional_type_def, get_decorator_name
from src.core.Plugins.Python.Endpoints.ModelManagerBase import ModelManagerBase
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import EMPTY
from src.gl.Enums import Output, Color, MessageSeverity
from src.gl.Message import Message
from src.gl.Parse.Parser_Java import Parser_Java
from src.gl.Validate import isInt

ENTITY = 'Entity'
STRING_TYPES = ('string', 'text')


class SpringModelManager(ModelManagerBase):

    def __init__(self):
        scanner = Scanner(
            base_dir=Session().input_dir,
            file_type='java')
        framework = Framework(FrameworkName.Spring, scanner=scanner)
        parser = Parser_Java()
        super().__init__(framework, parser=parser)

    def find_fields(self):
        # Initialization
        self._messages.append(
            Message(f'{Color.GREEN} - {self._framework.name} attributes{Color.NC}', MessageSeverity.Completion))
        self._model_using_paths = [F.path for F in self._framework.findings if F.path is not None]

        # Get implementations of javax.persistence
        self._find_fields_of_container_type(ContainerType.Entity, pattern='@Entity')
        # Get implementations of lombok.Data
        self._find_fields_of_container_type(ContainerType.Data, pattern='@Data')

    def _find_fields_of_container_type(self, context_type, pattern):
        # a. Find paths using pattern
        self._framework.scanner.scan_dir(SearchPattern(pattern=pattern), output=Output.Object)
        findings = self._framework.scanner.findings
        paths = {F.path for F in findings}

        # b. Process all paths
        for path in paths:
            # Get file source code
            snippet = self._parser.get_snippet(path=path)
            if not snippet:
                self._error(f"Snippet not found for '{path}'")
                continue

            # Read snippet
            total_count, vulnerable_count, length = 0, 0, 0
            pattern_found, class_name = False, EMPTY
            vulnerable = True
            decorators = {}
            validated_field_names = []
            fields = []

            for line, line_no in snippet:
                line = line.strip()
                # Remember last class name from 1st line
                name = self._get_class_name_from_line(line=line, find=' class ')
                if name:
                    class_name = name
                    continue

                # Get field info
                if line.startswith(pattern):
                    pattern_found = True
                elif pattern_found:
                    # Start finding fields
                    if line.startswith('@'):
                        decorators[get_decorator_name(line)] = line
                    if context_type == ContainerType.Entity:
                        # Decorators
                        if line.startswith('@Column'):
                            length = self._get_length(line)
                            vulnerable = True

                    if '(' not in line:  # Skip methods
                        # Field found if access modifier (private, protect, public, package-private) or type found:
                        modifier_found = any(line.startswith(e) for e in AccessModifier.items)
                        field_type_found = '<' in line
                        if modifier_found or field_type_found:
                            fields.append(self._get_field(
                                context_type,
                                Element(path, line=line, line_no=line_no, class_name=class_name),
                                modifier_found, length, vulnerable, decorators))
                            # initialize
                            vulnerable = True
                            length = 0

            # Update the fields
            for F in fields:
                if F.name in validated_field_names:
                    F.vulnerable = False
                    F.title = SANITIZED_VIA_VALIDATOR

            total_count += len(fields)
            vulnerable_count = sum(F.vulnerable is True for F in fields)
            self._vulnerable_count += vulnerable_count

            # Completion message for this file
            if total_count > 0:
                self._messages.append(Message(completion_message_of_field_analysis(
                    context_type, class_name, total_count, vulnerable_count), MessageSeverity.Completion))

            # Add the fields to the bulk
            self._fields.extend(fields)

        # Completion messages for this pattern
        if self._vulnerable_count == 0:
            self._messages.append(Message(
                f'{Color.GREEN}No{Color.NC} '
                f'vulnerable string fields found in {len(paths)} {self._framework.name} {context_type}. ',
                MessageSeverity.Completion))
        else:
            self._messages.append(Message(
                f'{self._vulnerable_count} {Color.ORANGE}possible{Color.RED} '
                f'vulnerable string fields{Color.NC} found in {len(paths)} {self._framework.name} {context_type}. ',
                MessageSeverity.Completion))

    def _get_length(self, line) -> int:
        length = 0
        if self._parser.find_and_set_pos('length', set_line=line):
            length = self._parser.get_next_elem(ignore=['='])
        return length if isInt(length) else 0

    def _get_field(self, context_type, element, modifier_found, length, vulnerable, decorators) -> Field:
        """
        Example-1 with access modifier   : private String cidr;
        Example-2 without access modifier: List<EvsIPPoolDTO> evsIPPools;
        """
        delimiters = [';']
        self._parser.set_line(element.line)
        if modifier_found:
            self._parser.get_next_elem(delimiters=delimiters, LC=False)
        field_type = remove_optional_type_def(
            self._parser.get_next_elem(delimiters=delimiters, LC=False))
        element.name = \
            self._parser.get_next_elem(delimiters=delimiters, LC=False)
        # Add field
        if '@Enumerated' in decorators \
                or field_type.lower() not in STRING_TYPES:
            vulnerable = False
            title = f'{SANITIZED_BY_TYPE} validation detected.'
        else:
            title = f'Possible injection vulnerability in {field_type} attribute.'
        return Field(
            context_type=context_type,
            title=title,
            element=element,
            parent_name=element.class_name,
            field_type=field_type,
            length=length,
            vulnerable=vulnerable,
            decorators=decorators
        )
