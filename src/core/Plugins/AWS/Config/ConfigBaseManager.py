# ---------------------------------------------------------------------------------------------------------------------
# ConfigBaseManager.py
#
# Author      : Peter Heijligers
# Description : Json and Yaml configuration broker
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2022-05-17 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.DataLayer.CodeBase.Element import Element
from src.core.DataLayer.CodeBase.Endpoint import Endpoint
from src.core.DataLayer.CodeBase.Field import Field
from src.core.DataLayer.CoreModel import FD
from src.core.DataLayer.CoreReport import CoreReport
from src.core.DataLayer.Enums import SecurityPattern, ContextType, ConfigFileType
from src.core.DataLayer.Finding import Finding
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.AWS.AWS_Field import AWS_Field
from src.core.Plugins.AWS.Constants import RESOURCES, RESOURCE, ACTION, EFFECT, START_OF_ENDPOINTS, START_OF_MODELS, \
    ALLOW, DENY, START_OF_ENDPOINT, START_OF_MODEL
from src.core.Plugins.AWS.Enums import SchemaItem, EndpointItem
from src.gl.Const import EMPTY, APOSTROPHES
from src.gl.Enums import Color, Language, MessageSeverity
from src.gl.Functions import path_leaf_only, remove_color_code
from src.gl.GeneralException import GeneralException
from src.gl.Message import Message
from src.gl.Validate import isInt


class ConfigBaseManager(object):

    @property
    def file_type(self):
        return self._file_type

    @property
    def messages(self):
        return self._messages

    @property
    def rows(self):
        return self._rows

    @property
    def endpoints(self):
        return self._endpoints

    @property
    def fields(self):
        return self._fields

    @property
    def findings(self):
        return self._findings

    """
    Setters
    """

    @rows.setter
    def rows(self, value):
        self._rows = value

    def __init__(self, file_type: ConfigFileType):
        self._file_type = file_type
        self._messages = []
        self._rows = []
        self._endpoints = []
        self._endpoint = None
        self._endpoint_name = EMPTY
        self._fields = {}
        self._findings = []

    def analyze_policy_effect(self, effect):
        # Write Config findings
        SP = SearchPattern(pattern=SecurityPattern.Config, category_name=Language.General)
        self._parse_policies(effect, SP)

    def endpoint_analysis(self):
        pass

    def _merge_fields(self, input_fields, model_fields):
        if not input_fields:
            self._fields = model_fields
        if not model_fields:
            self._fields = input_fields

        # A. Merge fields
        if input_fields and model_fields:
            self._fields = input_fields
            input_field_names = [F.name for F in input_fields]
            for MF in model_fields:
                if MF.name not in input_field_names:
                    MF.vulnerable = False
                    MF.title = 'Model field does not exist as input parameter.'
                else:
                    for IF in input_fields:
                        if IF.name == MF.name:
                            MF.vulnerable = IF.vulnerable
                            MF.title = f"Model field references input parameter with text: '{IF.title}'." \
                                if IF.title else 'Model field references input parameter.'
            self._fields.extend(model_fields)
        # B. Reference evaluation
        vulnerable_containers = {F.parent_name for F in self._fields if F.vulnerable}
        sane_containers = {F.parent_name for F in self._fields if F.parent_name not in vulnerable_containers}
        # - Set references to sane containers to sane.
        for F in self._fields:
            if '$' in F.element.line:
                container_name = path_leaf_only(F.field_type)
                if container_name in sane_containers:
                    F.vulnerable = False
                    F.title = 'Model field refers to a sane container.'
                elif container_name in vulnerable_containers:
                    F.vulnerable = True
                    F.title = 'Model field refers to a vulnerable container.'

    @staticmethod
    def _get_fields(objects: dict, used_for_input=False) -> [Field]:
        """
        :param objects: Schema objects from the .yaml open api configuration
        :return: fields
        """
        aws_fields = []
        for obj_name, obj_items in objects.items():
            dir_name = obj_items[FD.CF_Dir_name]
            file_name = obj_items[FD.CF_File_name]
            line_no = obj_items[FD.CF_Line_no]  # container line no
            for field_name, attributes in obj_items[FD.CF_Items].items():
                field_type = EMPTY
                max_length = 0
                pattern = EMPTY
                for att_name, att_value in attributes.items():
                    if att_name == SchemaItem.Type:
                        if field_type != SchemaItem.Enum:
                            field_type = att_value
                    elif att_name == SchemaItem.Enum:
                        field_type = SchemaItem.Enum
                    elif att_name == SchemaItem.Pattern:
                        pattern = att_value
                    elif att_name == SchemaItem.MaxLength:
                        if isInt(att_value):
                            max_length = att_value
                    elif att_name == SchemaItem.Ref:
                        field_type = att_value
                # "Source line"
                line = EMPTY
                line = [f'{line}{att_name}={att_value}, ' for att_name, att_value in attributes.items()]
                line = f'{field_name} attributes: {EMPTY.join(line)[:-2]}' \
                    if len(line) > 0 else EMPTY  # Convert to string
                # Add AWS_field
                aws_fields.append(
                    AWS_Field(
                        context_type=ContextType.Config,
                        name=field_name,
                        field_type=field_type,
                        max_length=max_length,
                        pattern=pattern,
                        parent_name=obj_name,
                        element=Element(
                            path=f'{dir_name}{file_name}', name=field_name, line=line, line_no=line_no),
                    ))
        # Convert AWS_Fields to Fields
        fields = []
        for F in aws_fields:
            fields.append(Field(
                context_type=F.context_type,
                element=F.element,
                parent_name=F.parent_name,
                vulnerable=F.vulnerable,
                title=F.title,
                field_type=F.field_type,
                length=F.max_length,
                used_for_input=used_for_input
            ))
        return fields

    def _get_info_from_csv(self, find_key) -> dict:
        """ Find "paths" (endpoints) or "schemas" (objects)
        I: CSV Output of ConfigParser(ConfigFileType.Yaml)
        Example for "schemas":

        Dir FileName                    Row#    Level   Key             Value
        /   myProject_openapi_aws.yaml	206	    5	    ServiceAddress
        /   myProject_openapi_aws.yaml	207	    7	      type	        object
        /   myProject_openapi_aws.yaml	208	    7	      properties
        /   myProject_openapi_aws.yaml	209	    9	        postalCode
        /   myProject_openapi_aws.yaml	210	    11	          type	    string
        /   myProject_openapi_aws.yaml	211	    11	          pattern	'^\\w{6}$'
        /   myProject_openapi_aws.yaml	212	    9	        houseNumber
        /   myProject_openapi_aws.yaml	213	    11	          type	    integer
        """
        if find_key not in (START_OF_ENDPOINTS, START_OF_ENDPOINT, START_OF_MODELS, START_OF_MODEL,):
            raise GeneralException(f"{__name__}: Unsupported find_key '{find_key}'.")

        start_of_fields = EMPTY
        if find_key in (START_OF_ENDPOINTS, START_OF_ENDPOINT):
            start_of_fields = EndpointItem.Parameters
        elif find_key in (START_OF_MODELS, START_OF_MODEL):
            start_of_fields = SchemaItem.Properties

        items, fields, field_attributes = {}, {}, {}
        if not self._rows or len(self._rows) < 2:
            return {}

        try:
            d = CoreReport(CoreReport.ConfigFile).map_header_to_0_based_colno_dict(CoreReport.ConfigFile, self._rows[0])
        except GeneralException:
            raise

        row_no = 1
        start, suspend = False, False
        start_level, item_level, fields_level, field_level = 0, 0, 9999, 9999
        item_name, field_name = EMPTY, EMPTY

        # Csv rows (converted from .yaml)
        for row in self._rows[1:]:
            row_no += 1

            row_dir_name = row[d[FD.CF_Dir_name]]
            row_file_name = row[d[FD.CF_File_name]]
            row_level = int(row[d[FD.CF_Level]])
            row_key = row[d[FD.CF_Key]]
            row_value = row[d[FD.CF_Value]]
            row_line_no = row[d[FD.CF_Line_no]]

            # End Of Items
            if (start and row_level <= start_level) or (row_level < item_level):
                # Last time
                return self._add_item(find_key, items, item_name, fields, field_name, field_attributes)

            # Start at "path(s)" or "schema(s) (1)"
            if row_key.lower() == find_key:
                start = True
                start_level = row_level
                # Single path or schema: Start right away
                if find_key in (START_OF_ENDPOINT, START_OF_MODEL) and item_level == 0:
                    item_level = row_level
            # Remember item level (first row after the trigger), a "path" or "schema" (3)
            elif start and item_level == 0:
                item_level = row_level

            # Level break item ("path" or "schema")(3):
            if row_level == item_level:
                # Add previous (cumulative)
                items = self._add_item(find_key, items, item_name, fields, field_name, field_attributes)
                # Initialize new
                item_name = row_key
                fields, field_name, field_attributes = {}, EMPTY, {}
                field_level, fields_level = 9999, 9999
                items[item_name] = {
                    FD.CF_Dir_name: row_dir_name,
                    FD.CF_File_name: row_file_name,
                    FD.CF_Line_no: row_line_no,
                    FD.CF_Items: {}  # Schema properties or Endpoint parameters
                }

            # No ("path" or "schema") has been reached yet
            if not item_name:
                continue

            # Remove apostrophes from value
            for i in APOSTROPHES:
                row_value = row_value.replace(i, EMPTY)

            # Endpoint initialization
            if find_key == START_OF_ENDPOINTS:
                # Endpoint uri
                if row_level == item_level:
                    items[item_name][FD.CF_Endpoint_uri] = row_key
                    continue
                # Next row (get, put, post)
                elif row_level > item_level and not items[item_name].get(FD.CF_Http_method):
                    items[item_name][FD.CF_Http_method] = row_key
                # Endpoint name
                if row_key == EndpointItem.OperationId:
                    items[item_name][FD.CF_Operation] = row_value
                    continue

            # "properties"/"parameters" found: save level (7)
            if row_key == start_of_fields:
                suspend = False
                fields_level = row_level
                continue

            # Suspend mode: Level break "properties"/"parameters": search again for new "start_of_fields".
            elif row_level <= fields_level or suspend:
                suspend = True
                continue

            # Field attribute level (11)
            # Add the Field attribute (like "type: string", "max_length: 25" or "pattern: '^\w{6}$'")
            if row_level > field_level:
                field_attributes[row_key] = row_value
            # Field level (9)
            # Add the field (like "city:")
            elif row_level > fields_level:
                # Save previous
                if field_name:
                    fields[field_name] = field_attributes
                # Initialize new
                field_level = row_level
                if find_key == START_OF_ENDPOINTS and row_key == SchemaItem.Name:
                    field_name = row_value
                else:
                    field_name = row_key
                fields[field_name] = {}
                field_attributes = {}

        # Last time
        return self._add_item(find_key, items, item_name, fields, field_name, field_attributes)

    def _add_item(self, find_key, items, item_name, fields, field_name, field_attributes) -> dict:
        """ Add the new endpoint or schema dictionary to the main dictionary. """
        if not item_name or item_name not in items:
            return items
        if field_name:
            fields[field_name] = field_attributes
        d = items[item_name]
        d[FD.CF_Items] = fields
        # Add Endpoints
        if find_key == START_OF_ENDPOINTS:
            self._add_endpoint(d)
        return items

    def _add_endpoint(self, d):
        """
        Convert dictionary to Endpoint and Fields objects
        """
        path = f'{d.get(FD.CF_Dir_name)}{d.get(FD.CF_File_name)}{d.get(FD.CF_Endpoint_uri)}'
        self._endpoint = Endpoint(
            Element(name=d.get(FD.CF_Operation), path=path, method_name=d.get(FD.CF_Http_method),
                    line_no=d.get(FD.CF_Line_no)), method_name=d.get(FD.CF_Http_method))
        self._endpoints.append(self._endpoint)

    def _parse_policies(self, effect, sp: SearchPattern):
        self._findings = []
        if not self._rows or len(self._rows) < 1:
            return []

        try:
            d = CoreReport(CoreReport.ConfigFile).map_header_to_0_based_colno_dict(CoreReport.ConfigFile, self._rows[0])
        except GeneralException:
            raise

        find_mode, level, name = False, 0, EMPTY
        resources_mode, resource_name, resource_mode, resource_mode = False, EMPTY, EMPTY, EMPTY
        resources_level, resource_level, resource_mode_level = 0, 0, 0
        sid = EMPTY
        actions = []
        row_no = 1
        for row in self._rows[1:]:
            row_no += 1
            row_level = int(row[d[FD.CF_Level]])
            row_key = row[d[FD.CF_Key]]
            row_value = row[d[FD.CF_Value]]

            # Remember resource (= name after "Resources") (i.e. last one on same level)
            if row_key == RESOURCES:  # Here the list of resources starts
                resources_mode = True
                resources_level = row_level
            elif resources_mode:
                # New resource name
                if not resource_name or row_level == resource_level:
                    resource_name = row_key
                    resource_level = row_level
                # "RESOURCE", "ACTION"
                if row_key in (RESOURCE, ACTION):
                    resource_mode = row_key
                    resource_mode_level = row_level
                elif row_level <= resource_mode_level:
                    resource_mode = EMPTY
                    actions = []

            # Resources level break
            if row_level < resources_level:
                sid = EMPTY

            # Remember Sid
            if row_key.lower() == 'sid':
                sid = row_value

            if resource_mode == ACTION:
                if row_key and row_value:
                    actions.append(row_value)

            # Allow / Deny found
            if row_key == EFFECT and row_value == effect:
                find_mode = True
                level = row_level

            # Allow / Deny level break
            if find_mode and row_level < level:
                find_mode = False
                continue
            if find_mode and (
                    (effect == ALLOW and '*' in row_value) or
                    (effect == DENY and '*' not in row_value)
            ):
                path = f'{row[d[FD.CF_Dir_name]]}/{row[d[FD.CF_File_name]]}'
                for_sid = f' {Color.GREEN}{sid}{Color.NC}' if sid else EMPTY
                for_actions = f" actions {Color.GREEN}[{', '.join(actions)}]{Color.NC}" if actions else EMPTY
                sid_actions_text = f'for{for_sid}{for_actions}' if (for_sid or for_actions) else EMPTY
                line_no = row[d[FD.CF_Line_no]]
                finding = f'{effect} {resource_mode} ' \
                          f'{Color.ORANGE}{row_value}{Color.NC} ' \
                          f'{sid_actions_text} in resource {Color.GREEN}{resource_name}{Color.NC} ' \
                          f'may be too permissive. '
                self._messages.append(Message(f'File {path}:{line_no}: {finding}', MessageSeverity.Completion))
                self._findings.append(Finding(
                    search_pattern=sp, base_dir=row[d[FD.CF_Dir_name]], file_name=row[d[FD.CF_File_name]], path=path,
                    line=remove_color_code(finding), line_no=line_no))
