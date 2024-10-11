# ---------------------------------------------------------------------------------------------------------------------
# GetDatFlow.py
#
# Author      : Peter Heijligers
# Description : Get data flow in method
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2019-06-11 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.Plugins.Const import CLASS, TYPE_PROPERTY, TYPE_METHOD, TYPE_CLASS, INPUT, FLOW, OUTPUT, \
    DEFINITION, CONDITION, ASSIGNMENT, OPERATOR, CONSTANT, PRIMITIVE, PARAMETER, PARAMETER_NAME, RETURN, \
    ASSIGNMENT_TARGET, ASSIGNMENT_SOURCE, PARAMETER_TYPE
from src.core.DataLayer.CodeBase.ParameterFlow import ParameterFlow
from src.core.Plugins.Python.DataFlow.Model.DataFlowPython import DataFlowPython
from src.gl.Const import BLANK, MAX_LOOP_COUNT, EMPTY, UNKNOWN
from src.gl.Parse.Parser_Python import CRLF, TAB, DEF, Parser_Python
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrCtl, ErrorType
from src.core.Plugins.Python.DataFlow.Model.MethodSignature import MethodSignature

PGM = 'GetDataFlow'
prefix = f'{PGM} class: '

path = None
error_message = None
EOL = False
EOF = False
stmt = EMPTY
line = None
line_no = 0
delimiter = None
delimiter_p = None
pos = 0
start_pos = 0
loop_count = 0
parent = None
hooks = 0
flow_mode = None
debug = False
assignment = False

delims = ['(', ',', ':', ')', '.', '{', '}']
method_delims = ['(', ',', ')', '.', '=', ':']

parser = Parser_Python()

"""
Get flow analysis for a specific endpoint.
E.g. method "post" with 3 parameters, returns analysis for 3 data flows of the 3 parameters.
    Every parameter may result in multiple data flows.
"""


class DataFlowParser(object):
    def __init__(self):
        pass

    def get_parameter_flows(self, E: Element, linked_to_vulnerable_serializer: bool = False, debug_mode=False,
                            session=None, framework=None) -> [ParameterFlow]:
        global path, stmt, EOF, debug, loop_count

        path = E.path
        method_name = E.method_name
        class_name = E.class_name
        debug = debug_mode
        E_params = []

        # Get the snippet
        find_type = CLASS
        find_name = class_name
        method_name_if_class = None
        if method_name:
            if class_name:
                method_name_if_class = method_name
            else:
                find_type = DEF
                find_name = method_name

        statements = parser.get_snippet(find_type=find_type, path=path, find_name=find_name,
                                        method_name_if_class=method_name_if_class)
        if not statements:
            return []

        # Container: Parser has remembered last class name
        class_name = parser.class_name if not class_name else class_name
        # Find the parameters of the method definition
        stmt = statements[0][0]
        line_no_start = statements[0][1]

        # Get method name
        self._ini_read()
        self._get_next_elem()  # skip 'def' or 'class'
        method = self._get_next_elem(delimiters=['('])
        if method == DEF:  # if async, now skip "def"
            method = self._get_next_elem(delimiters=['('])
        if not method or method != method_name:
            return []

        # Get method parameters
        self._ini_read()  # Start reading again e.g. to reset hooks.
        loop_count = 0
        skip_next = False

        while not EOL:
            self._loop_increment(f"Unable to find_file method parameters in '{stmt}'.")  # Check infinite loop
            element = self._get_next_elem(delimiters=method_delims)
            E = self._get_Element(element)

            if E and E.flow_type == PARAMETER and E.data_type != PRIMITIVE and not skip_next \
                    and E.value not in ['self', '*args', '**kwargs']:
                E_params.append(E)
            if delimiter == ')':
                break
            skip_next = delimiter == ':'  # parameter type

        # - Method signature
        method_signature = MethodSignature(
            path=path, class_name=class_name, method_name=method_name,
            line_no_start=line_no_start, parameters=E_params)

        # Get all method parameter data flows and the flow_result.
        PFs = self._get_parameter_flows(method_signature, statements, linked_to_vulnerable_serializer, session,
                                        framework)
        return [PF for PF in PFs if not PF.error_message and PF.parameter_used]

    """
    Get the data flows (incl. flow results) of 1 endpoint (get/put/post).
    E.g. 3 data flows if there are 3 parameters.
    """

    def _get_parameter_flows(self, method_signature, statements, linked_to_vulnerable_serializer,
                             session=None, framework=None) -> [ParameterFlow]:
        """
        Get results for all parameters of 1 method
        """

        if not method_signature or not statements:
            return []

        # a. Get the enriched method statements (after "def"). [stmtNo, [Elements]]
        statements_Elements = [[s[0], self._get_stmt_elements(s)] for s in statements]

        # b. For every method input parameter: get the valid data flow(s).
        parameter_flows = [self._get_parameter_flow(
            E, method_signature, statements_Elements, linked_to_vulnerable_serializer, session, framework)
            for E in method_signature.parameters]
        return parameter_flows

    def _get_parameter_flow(self, E, method_signature, statements_Elements, linked_to_vulnerable_serializer, session,
                            framework) -> ParameterFlow:
        """
        Get local flow for 1 method parameter
        """
        global flow_mode
        input_parameter = E.value

        DFs = []
        DF = DataFlowPython(elements=[E])
        last_node = False
        flow_mode = INPUT
        first_method = True
        parent_value = None

        # For every full statement
        for stmt_enriched in statements_Elements:
            E_assignment_target, E_parent = None, None
            statement = stmt_enriched[0]
            if debug:
                print(f'statement: {statement}')

            stmt_values = {E.value for E in stmt_enriched[1]}

            # For every Element in the line
            for E in stmt_enriched[1]:
                if debug:
                    print(f'  element: value={E.value}, flow_type={E.flow_type}')

                if E.flow_type == ASSIGNMENT_TARGET:
                    # Assignment: e.g. "target = source1 + source2" or "data = modify(request.data)"
                    E_assignment_target = E
                    if any((tainted in stmt_values) for tainted in DF.tainted_values):
                        if E_assignment_target:
                            DF.add_tainted(E_assignment_target)
                elif E.flow_type == TYPE_CLASS:
                    E_parent = E
                elif E.flow_type == TYPE_METHOD:
                    if not first_method:
                        E_parent = E
                    first_method = False
                    if linked_to_vulnerable_serializer and E.value == 'is_valid':
                        DF.vulnerable = True
                    E.parent_value = parent_value
                elif E.flow_type == RETURN:
                    last_node = True

                # Element exists in the tainted values:
                if E.value in DF.tainted_values:
                    # a. Input parameter: Add to the flow:
                    # (1) parameter,
                    # (2) parent class/method,
                    # (3) assignment_target (opt)
                    if E.flow_type == PARAMETER:
                        DF.add_tainted(E)
                        DF.add_tainted(E_parent)
                        if E_assignment_target:
                            DF.add_tainted(E_assignment_target)
                    # b. Assignment_source: Add assignment_target to the flow (is influenced by the input parameter)
                    if E.flow_type == ASSIGNMENT_SOURCE:
                        DF.add_tainted(E_assignment_target) if E_assignment_target \
                            else self._error_control('Assignment without target!')
                    # c. Output: Add output to the flow (is influenced by the parameter)
                    if last_node and E.flow_mode == OUTPUT:
                        DF.add_tainted(E)

                # Save method class name
                if E.flow_type == TYPE_CLASS:
                    parent_value = E.value
                else:
                    parent_value = None

            # Add returned element to the flow and add flow to flows.
            if last_node and DF not in DFs:
                DFs.append(DF)
                self._debug_df(DF)

            # Continue. Multiple return statements may exist.
            last_node = False

        # Last time (Todo: really needed?)
        if DF not in DFs:
            DFs.append(DF)
            self._debug_df(DF)

        # Get result
        return ParameterFlow(input_parameter, method_signature, DFs, session, framework)

    @staticmethod
    def _debug_df(df):
        if debug:
            debug_flow_value = [E.value for E in df.elements]
            debug_flow_type = [E.flow_type for E in df.elements]
            print(f' df: {debug_flow_value}')
            print(f' df: {debug_flow_type}')

    def _get_stmt_elements(self, statement) -> [Element]:
        """
        Get Elements = all Elements in the stmt
        """
        global flow_mode, stmt, assignment
        stmt = statement[0]
        lineNo = statement[1]
        assignment = False

        Elms = []
        self._ini_read()
        # 1st population of Elms
        element = self._get_next_elem(delimiters=delims)
        while element:
            E = self._get_Element(element)
            E.line = stmt
            E.pos = start_pos
            E.line_no = lineNo
            if E.flow_type == RETURN:
                flow_mode = OUTPUT
            E.flow_mode = flow_mode
            Elms.append(E)
            if flow_mode == INPUT:
                flow_mode = FLOW
            self._evaluate_hooks()
            element = self._get_next_elem(delimiters=method_delims if hooks > 0 else delims)

        # In case of an assignment, enrich the assignment types
        if len(Elms) > 2:
            if Elms[1].flow_type == ASSIGNMENT or assignment:
                Elms[0].flow_type = ASSIGNMENT_TARGET  # For both "t = s" and "t: T = s"
                for E in Elms:
                    if E.flow_type == UNKNOWN:
                        E.flow_type = ASSIGNMENT_SOURCE
        return Elms

    @staticmethod
    def _evaluate_hooks():
        global hooks
        if delimiter == '(':
            hooks += 1
        elif delimiter == ')':
            hooks -= 1 if hooks > 0 else 0

    def _get_Element(self, element) -> Element:
        global parent, hooks, delimiter_p

        element_lc = element.lower() if element else None

        if element_lc in ['def', 'class', 'import', 'from']:
            E = Element(value=element, flow_type=DEFINITION)
        elif element_lc in ['if', 'else', 'elif', 'do', 'while', '?', ':']:
            E = Element(value=element, flow_type=CONDITION)
        elif element in ['==', '!=', '>', '>=', '<', '<=']:
            E = Element(value=element, flow_type=OPERATOR)
        elif element == '=':
            flow_type = PARAMETER if hooks > 0 else ASSIGNMENT
            data_type = PARAMETER_TYPE if delimiter_p == ':' \
                else PARAMETER_NAME if hooks > 0 \
                else None
            E = Element(value=element, flow_type=flow_type, data_type=data_type)
        elif not element or type(element) in (int, float, None):
            E = Element(value=element, flow_type=PRIMITIVE)
        elif element[0] in ['"', '\'']:
            E = Element(value=element, flow_type=CONSTANT)
        # "parent" refers to previous flow_type, but freezes when reaching "(".
        # "flow_type"
        #              myClass.myMethod(parm1     =   request.  data)
        # flow_type := Class   Method   ParameterName Parameter Property
        # parent    := Class   Method   Method        Class   Property
        elif delimiter == '.':
            flow_type = PARAMETER if hooks > 0 else TYPE_CLASS
            parent = TYPE_CLASS
            E = Element(value=element.lstrip('*'), flow_type=flow_type, data_type=TYPE_CLASS)  # strip "*" and "**"
        elif delimiter == '(':
            self._evaluate_hooks()
            data_type = TYPE_METHOD if delimiter_p == '.' else TYPE_CLASS
            flow_type = TYPE_METHOD  # Class constructor is a method
            parent = flow_type
            E = Element(value=element, flow_type=flow_type, data_type=data_type)
        elif delimiter == '=':
            flow_type = PARAMETER if hooks > 0 else ASSIGNMENT
            data_type = PARAMETER_TYPE if delimiter_p == ':' \
                else PARAMETER_NAME if hooks > 0 \
                else None
            E = Element(value=element, flow_type=flow_type, data_type=data_type)
        elif delimiter in [',', ')', ':']:
            flow_type = PARAMETER
            if delimiter == ')':
                self._evaluate_hooks()
            if element_lc == 'none' or type(element) in (int, float, None):
                data_type = PRIMITIVE
            elif parent == TYPE_CLASS:
                data_type = TYPE_PROPERTY
            elif delimiter == ':' and hooks == 0:  # instance: MyClass = ...
                data_type = TYPE_PROPERTY
                flow_type = ASSIGNMENT
            else:
                data_type = PARAMETER
            E = Element(value=element, flow_type=flow_type, data_type=data_type)
        elif element_lc in ['return', 'exit']:
            E = Element(value=element, flow_type=RETURN)
        else:
            E = Element(value=element, flow_type=UNKNOWN)

        delimiter_p = delimiter
        return E

    # ---------------------------------------------------------------------------------------------------------------------
    # General routines
    # ---------------------------------------------------------------------------------------------------------------------
    def _read_statement(self, fo) -> str:
        global line, stmt, EOF, loop_count
        self._ini_read()

        line = self._read_line(fo)

        # Quick return: line contains whole statement
        if line.count('(') == line.count(')'):
            return line

        # Concat lines to stmt
        stmt = line
        closed_count, open_count, loop_count = 0, 0, 0
        while not EOF:
            # Check infinite loop
            self._loop_increment('Unable to find_file equal "(" and ")" counts.')
            # Sum hook counts
            open_count += line.count('(')
            closed_count += line.count(')')
            # Statement complete? Exit
            if closed_count == open_count:
                return stmt
            stmt += self._read_line(fo)

    @staticmethod
    def _ini_read():
        global pos, EOL, parent, delimiter, delimiter_p, hooks
        pos, hooks = 0, 0
        EOL = False
        parent = None
        delimiter, delimiter_p = None, None

    @staticmethod
    def _read_line(fo) -> str:
        global line, line_no, EOF, EOL
        EOF, EOL = False, False
        line = str(fo.readline())
        if not line or line == 'b\'\'':
            EOF, EOL = True, True
            return EMPTY
        else:
            # Remove byte representation ("b'mystring'") and crlf
            line = line[2:len(line) - 1].rstrip(CRLF)
            line_no += 1
            if not line:
                EOL = True
            return line

    def _get_next_elem(self, delimiters: list = None) -> str or None:
        global stmt, pos, EOL, delimiter, start_pos
        """
        1. Skip leading blanks and '.' then
        2. Gets the element and
        3. Skips the delimiter
        4. Skip trailing blanks
        """
        if not stmt:
            return None
        self._skip_blanks(ignore=['.', ')', ':', '='])  # 20191201: added ")". 20200121: added ":".
        # 20210924: added "=".
        start_pos = pos
        self._skip_non_blanks(delimiters)
        next_elem = stmt[start_pos:pos] if pos > start_pos else None

        if not EOL and next_elem:
            if delimiters:
                if stmt[pos] in delimiters:
                    delimiter = stmt[pos]
                    self._add_1_pos()
                    self._skip_blanks()
                else:
                    next_elem = None
        return next_elem

    def _skip_blanks(self, ignore=None):
        global stmt, pos, EOL, assignment
        ignore = self._add_blank(ignore)
        while not EOL and stmt and stmt[pos] in ignore:
            if stmt[pos] == '=':
                assignment = True
            self._add_1_pos()

    def _skip_non_blanks(self, delimiters: list = None):
        global stmt, pos, EOL, delimiter
        if pos >= 0 and stmt:
            delimiters = self._add_blank(delimiters)
            while not EOL and stmt[pos] not in delimiters:
                self._add_1_pos()
            delimiter = None if pos >= len(stmt) else stmt[pos]

    @staticmethod
    def _add_blank(values) -> list:
        if not values:
            values = [BLANK, TAB]
        else:
            if BLANK not in values:
                values.extend(BLANK)
            if TAB not in values:
                values.extend(TAB)
        return values

    @staticmethod
    def _add_1_pos():
        global stmt, pos, EOL
        if pos < len(stmt):
            pos += 1
        if pos >= len(stmt):
            EOL = True

    def _loop_increment(self, message):
        global loop_count, EOF, EOL
        loop_count += 1
        if loop_count > MAX_LOOP_COUNT:
            self._error_control(message)
            EOF, EOL = True, True

    @staticmethod
    def _error_control(error_text):
        global line_no, path, prefix
        ErrCtl().add_line(ErrorType.Error, f"{prefix} error at line {line_no}: {error_text}. Path is '{path}'")
