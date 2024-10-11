# ---------------------------------------------------------------------------------------------------------------------
# JsonManager.py
#
# Author      : Peter Heijligers
# Description : JavaScript plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-07-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.DataLayer.Enums import ConfigFileType
from src.core.Plugins.AWS.Config.ConfigBaseManager import ConfigBaseManager
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Enums import MessageSeverity
from src.gl.Message import Message
from src.gl.Parse.Parser_Python import Parser_Python

PGM = 'JsonManager'

parser = Parser_Python()
csvm = CsvManager()
FM = Findings_Manager()

"""
Json policies example:
  "Statement": [
    {
      "Sid": "AllowReadOnlySSM",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "*"
    },
"""


class JsonManager(ConfigBaseManager):

    def __init__(self):
        super().__init__(ConfigFileType.Json)

    def endpoint_analysis(self):
        self._messages.append(Message(f'{__name__}: Json endpoint analysis has not been implemented yet.',
                                      MessageSeverity.Completion))
