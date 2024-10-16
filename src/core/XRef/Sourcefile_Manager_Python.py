# ---------------------------------------------------------------------------------------------------------------------
# Sourcefile_Manager_Python.py
#
# Author      : Peter Heijligers
# Description : Build a call x-ref from a source file.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os

from src.core.DataLayer.CodeBase.Import import Import
from src.core.DataLayer.Enums import ClassSourceUsage
from root_functions import slash
from src.core.XRef.Sourcefile_Manager_Base import *
from src.gl.Const import BLANK, EMPTY
from src.gl.Functions import path_leaf, loop_increment
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrCtl, ErrorType

PGM = 'Sourcefile_Manager_Python'

""" 
Precondition: pos always on 1st position of the item to be processed, or -1
"""


class Sourcefile_Manager_Python(Sourcefile_Manager_Base):

    @property
    def error_message(self):
        return self._error_message

    @property
    def warning_messages(self):
        return self._warning_messages

    def __init__(self, db=None, store_external_library_calls=False):
        super().__init__(db, store_external_library_calls)

    def parse_file(self, path, def_mode, base_dir) -> bool:
        self._this_ns, self._module_name = path_leaf(path)
        this_ns = f'{self._this_ns}{slash()}'.replace(base_dir, EMPTY)
        self._this_ns = '.' if self._this_ns and not this_ns else this_ns
        self._this_class_name = self._module_name
        bare_module_name, file_ext = os.path.splitext(self._module_name)

        # Validate
        self._prefix = f"{PGM} source file '{self._module_name}': "
        if file_ext not in supported_file_types:
            self.warning_messages.append(
                f"{self._prefix} error: Extension '{file_ext}' is not supported in path '{path}'")
            return True

        # Parse
        self._parse(path, def_mode)
        return True if not self.error_message else False

    def _parse(self, path, def_mode=False):
        """
        :param path: source file path
        :param def_mode: True = get definitions first
        """
        # Open file for reading, converting binary to string (utf-8)
        try:
            fo = open(path, 'rb')
            parser.ini_file(self._this_ns)
            parser.read_line(fo)

            # Loop until EOF
            while not self.error_message and parser.line != EOF:
                if parser.line and not parser.is_comment:
                    # find_file 1st element
                    first_elem = parser.get_next_elem()
                    # Import (only in 1st step = definition mode)
                    if first_elem in [IMPORT, FROM] and def_mode:
                        self._set_Import_def(first_elem, def_mode=def_mode)
                    # Class
                    elif first_elem == CLASS:
                        self._set_Class_def(def_mode=def_mode)
                    # Method
                    elif first_elem == DEF:
                        self._set_Method_def(def_mode=def_mode)
                    # 2nd time
                    elif not def_mode:
                        line_w = parser.line.lstrip()
                        if line_w and not line_w.startswith('.'):
                            self._set_Method_call()
                if self.error_message:
                    ErrCtl().add_line(
                        ErrorType.Error, f"{self._prefix} error at line {parser.line_no}: '{parser.line}'")

                # Next line
                parser.read_line(fo)
            fo.close()
        except IOError as e:
            self._error_message = f"{self._prefix} error: {e.args[1]} at path '{path}'"

    def _set_Import_def(self, item, def_mode=False):
        # Add module if a import is found
        self._set_Module_def(def_mode)

        # (from ... )import ..., ... (as ...)
        # a. From ... import
        from_location = None
        if item == FROM:
            from_location = parser.get_next_elem(ignore=[])
            import_kwd = parser.get_next_elem()
            if import_kwd != IMPORT:
                if 'FROM' not in parser.line:  # May be part of SELECT statement
                    ErrCtl().add_line(
                        ErrorType.Warning, f'{self._prefix} warning: Import expected at line {parser.line_no}')
                return

        # b. ..., ... (as ...)
        # Save classes and map aliases
        import_location, import_class_name = parser.split_last_node(parser.get_next_elem(LC=False))
        location = from_location if from_location else import_location

        while loop_increment(f'{__name__}.set_import_def'):
            # local_class_name = parser.get_next_elem( LC=False ) if parser.get_next_elem() == AS else class_name

            elem = parser.get_next_elem(delimiters=[','], LC=False)
            local_class_name = parser.get_next_elem(delimiters=[','], LC=False) if elem == AS else elem
            # e.g. "import c1" does not have a local class name
            class_name = local_class_name if local_class_name else import_class_name

            if def_mode and self._db:
                self._class_manager.add_class(module_id=self._module_id, line_no=parser.line_no,
                                              source_usage=ClassSourceUsage.Import, class_name=class_name,
                                              ns=self._this_ns, module_name=self._module_name,
                                              class_type_namespaces=[], class_type_names=[],
                                              local_class_names=self._local_class_names)

            class_Import = Import(class_name=import_class_name, location=location, local_class_name=local_class_name)
            self._local_class_names[local_class_name] = class_Import
            if parser.EOL:
                break

    def _set_Module_def(self, def_mode=False):
        if def_mode and self._db:
            self._module_id = self._module_manager.insert(
                ns=self._this_ns,
                module_name=self._module_name,
            )
            if not self._module_id:
                self._module_id = 0

    def _set_Class_def(self, def_mode=False):
        # Add module if a class or method is found
        self._set_Module_def(def_mode)

        # class ...([class_type_ns.]class_type-1, class-type-2):
        self._current_class = parser.get_next_elem(delimiters=[BLANK, '(', ':'], LC=False)

        # Extract the ns from the type (e.g. "class MyClass(common.MySuper)")
        class_type_names, class_type_nss = [], []
        class_type_ns, class_type_name = EMPTY, EMPTY

        if parser.delimiter == '(':
            while loop_increment(f'{__name__}.set_class_def: {parser.line}'):
                elem = parser.get_next_elem(delimiters=[')', '.', ','], LC=False)
                if parser.delimiter == '.':
                    class_type_ns = elem
                else:
                    class_type_name = elem.replace(',', EMPTY) if elem else EMPTY
                if class_type_name:
                    class_type_nss.append(class_type_ns)
                    class_type_names.append(class_type_name)
                class_type_ns, class_type_name = EMPTY, EMPTY
                if parser.EOL or parser.delimiter == ')':
                    break

        # When the only class type is "object", then there are no superclasses.
        self._current_class_types = [] \
            if len(class_type_names) == 1 and class_type_names[0].lower() in CLASSES_IGNORE \
            else class_type_names

        if def_mode and self._db:
            self._class_manager.add_class(module_id=self._module_id, line_no=parser.line_no,
                                          source_usage=ClassSourceUsage.Def, class_name=self._current_class,
                                          ns=self._this_ns, module_name=self._module_name,
                                          class_type_namespaces=class_type_nss,
                                          class_type_names=self._current_class_types,
                                          local_class_names=self._local_class_names)

    def _set_Method_def(self, def_mode=False):
        # Add module if a class or method is found
        self._set_Module_def(def_mode)

        # def ...(p1, p2)
        method_name = parser.get_next_elem(delimiters=['('], LC=False)
        if not method_name or method_name in METHODS_IGNORE:
            return

        self._current_method = method_name

        if def_mode and self._db:
            self._method_manager.add_method_by_parser(
                parser=parser,
                method_name=method_name,
                current_class_name=self._current_class,
                ns=self._this_ns)

    def _set_Method_call(self):
        # line example-1: [self|class_type|c1].m1(p1, p2)
        # line example-2: save()

        # validation
        if not self._db:
            return

        parser.find_and_set_pos('(')
        hook = parser.pos > -1
        if not hook:  # "(" is required
            return

        parser.find_and_set_pos('.')
        dot = parser.pos > -1

        # Class name
        called_class_name = self._get_class_name(dot)

        # Method name
        parser.find_and_set_pos('(')  # reset pointer
        called_method_name = parser.get_prv_elem(skip_first=['('], delimiters=['.'], LC=False)

        if called_method_name:
            self._call_manager.add_call_by_parser(
                self._current_class, self._current_method, called_class_name, called_method_name, parser)

    def _get_class_name(self, dot) -> str:

        # E.g. "save()"
        if not dot:
            return self._current_class

        # Pointer is on first "."
        # E.g. [self|class_type|c1].c1.m2(p1, p2)

        # First element
        called_class_name = parser.get_prv_elem(skip_first=['.'], LC=False)
        if called_class_name in ['self', 'cls']:
            called_class_name = self._current_class
        elif called_class_name == 'super':
            if not self._current_class_types:
                called_class_name = EMPTY
            elif len(self._current_class_types) == 1:
                called_class_name = self._current_class_types[0]
            else:
                called_class_name = '*MANY'
        elif called_class_name and called_class_name in self._local_class_names:
            called_class_name = self._local_class_names[called_class_name].class_name

        # Reset pointer on first "."
        parser.get_next_elem(delimiters=['.'], LC=False)
        # Read until "(". Substitute last class, e.g. "pipeline" in "self.pipeline.process(p1, p2,)"
        while parser.delimiter == '.' and loop_increment(f'{__name__}.get_class_name'):
            e = parser.get_next_elem(delimiters=['(', '.'], LC=False)
            if parser.delimiter == '.':
                called_class_name = e

        if not called_class_name:
            ErrCtl().add_line(
                ErrorType.Error, f"{self._prefix} error: called class name not found in '{parser.line}'")
            return EMPTY

        return called_class_name
