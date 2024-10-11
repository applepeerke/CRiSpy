# Purpose: Analyze config files in JSON format (AWS, Terraform, ...)
import os

from src.core.DataLayer.Enums import ConfigFileType
from src.core.Functions.Functions import strip_line
from src.core.Plugins.AWS.Config.ConfigParser import ConfigParser
from src.gl.Const import EMPTY
from src.gl.Enums import MessageSeverity
from src.gl.Message import Message

""" 
Example:
--------
resource "aws_s3_bucket" "test_data" {
  bucket = join("", [local.name_prefix, "data", local.name_suffix])
  acl    = "private"
  tags   = local.common_tags

  # Prevent from destroying or replacing this object
  lifecycle {
    prevent_destroy = true
  }
"""


class JsonConfigToCsv(ConfigParser):

    def __init__(self):
        super().__init__(ConfigFileType.Json)
        self._input_path = EMPTY
        self._input_dir = EMPTY

    def _get_file_data(self, input_path, input_dir) -> list:
        """
        Get every "type name {[key = value]}" block in the file.
        A "value" may contain a {} block itself, only a simple one is supported yet.
        """
        self._input_path = input_path
        self._input_dir = input_dir

        # Get the file and check if it is JSON
        lines = []
        json = False
        _, ext = os.path.splitext(input_path)

        try:
            with open(input_path, encoding='utf-8-sig') as file:
                for line in file:
                    if line.startswith('}'):
                        json = True
                    line = strip_line(line)
                    lines.append(line)
        except UnicodeDecodeError as ue:
            if 'start byte' in str(ue):
                if ext:
                    self._blacklist.add(ext)
            else:
                self._messages.append(Message(f'Not processed: {input_path}. Reason: {ue}', MessageSeverity.Error))
        if not json:
            return []

        # Get data from lines
        self._file_name = os.path.basename(input_path)
        self._rows, list_values = [], []
        self._item_type, self._item_names, self._item_key, self._item_values = EMPTY, [], EMPTY, EMPTY
        level, level_list, line_no = 0, 0, 0

        for line in lines:
            line_no += 1

            if line == 'EOF':  # TerraForm may contain buggy structure with too few "}" when ending with "EOF".
                level, level_list = 0, 0
                continue

            # Split the line "myKey = myValue {" in items like ["myKey", "=", "myValue", "{"]
            # Example: "myKey = myValue {" -> ["myKey", "=", "myValue", "{"]
            self._items = line.split()
            # Skip empty lines or comment
            if not self._items or self._items[0] in ['#', '//', '/*', '*/']:
                continue

            # Block start
            if line.endswith('{'):
                if level == 0:
                    self._item_type = self._items[0]
                    self._item_names = [i for i in self._items[1:] if i != '{']  # Concat all values until "{"
                else:  # Complex type
                    self._item_key = self._sophisticate(self._items[0])
                    if self._item_key != '{':  # Only if information exists
                        self._item_value = EMPTY
                        self._add_row(line_no, level)
                level_list = 0  # End simple list processing
                level += 1
                continue

            # Block end
            if line.endswith('}'):
                level -= 1
                continue
            elif line.endswith('['):
                # Add key
                self._item_key = self._sophisticate(self._items[0])
                self._item_value = EMPTY
                self._add_row(line_no, level)
                list_values = []
                level_list += 1
                level += 1
            elif line.endswith(']'):
                # Add values
                if list_values:
                    level += 1
                    for self._item_value in list_values:
                        self._add_row(line_no, level)
                    level -= 1
                    list_values = []
                level_list -= 1
                level -= 1

            # "Key = Values" or "Key: Values", and last element <> "["
            if self._items[len(self._items) - 1] != '[':
                if len(self._items) > 1 and (self._items[1] == '=' or self._items[0].endswith(':')):
                    self._item_key = self._items[0] if self._items[1] == '=' else self._items[0:-1]
                    self._item_key = self._sophisticate(self._item_key)
                    self._item_value = self._sophisticate([i for i in self._items[1:] if i != '='])
                    self._add_row(line_no, level)
                elif level_list > 0:
                    list_values.append(self._sophisticate([i for i in self._items]))
        return self._rows

    def _add_row(self, line_no, level):
        self._rows.append([
            self._input_path.replace(self._input_dir, EMPTY),
            self._file_name,
            line_no,
            self._item_type,
            self._item_names,
            level,
            self._item_key,
            self._item_value]
        )

    def _sophisticate(self, values) -> str:
        if isinstance(values, list):
            v = str(values)
            if ',' in v:
                return v
            v = [self._sophisticate_value(item) for item in values]
            return ','.join(v)
        else:
            return self._sophisticate_value(values)

    @staticmethod
    def _sophisticate_value(item) -> str:
        if item:  # may be ""
            if item.endswith(':'):
                item = item[:-1]
            item = item.replace('"', EMPTY)
            item = item.replace("'", EMPTY)
        return item
