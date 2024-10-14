# Purpose: Analyze config files in Yaml format (AWS, ...)
import os

from src.core.DataLayer.Enums import ConfigFileType
from src.core.Functions.Functions import strip_line
from src.core.Plugins.AWS.Config.ConfigParser import ConfigParser
from src.gl.Const import EMPTY

DELIM = ':'

""" 
Example:
--------
  HealthCheckFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub "${ApplicationNamePrefix}-health-check"
      CodeUri: ai-lambdas-${project.version}.jar
      Handler: com.myComp.mapps.ai.lambda.HealthCheckLambda::handleRequest
      Events:
        AccessInfo:
          Type: Api
          Properties:
            Path: /health
            RestApiId: !Ref AccessInfoApi
            Method: GET
      VpcConfig:
        SecurityGroupIds:
          - !Ref LambdaSecurityGroup
      Policies:
        - Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Action:
                - logs:CreateLogStream
                - logs:PutLogEvents
                - ec2:CreateNetworkInterface
                - ec2:DescribeNetworkInterfaces
                - ec2:DeleteNetworkInterface
              Resource:
                - !Sub "arn:aws:logs:${AWS::Region}::${AWS::AccountId}:log-group/${ApplicationNamePrefix}-health-check"
                - !Sub "arn:aws:logs:${AWS::Region}::${AWS::AccountId}:log-group/${ApplicationNamePrefix}-health-check:
                log-stream:*"
        - Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
              Resource: "*"
"""


class YamlConfigToCsv(ConfigParser):

    def __init__(self):
        super().__init__(ConfigFileType.Yaml)

    def _get_file_data(self, input_path, input_dir) -> list:
        """
        Get every "name key: value" in the file.
        """

        # Get the file
        with open(input_path, encoding='utf-8-sig') as file:
            lines = file.readlines()

        # Get data from lines
        file_name = os.path.basename(input_path)
        dir_name = input_path.replace(input_dir, '/').replace(file_name, EMPTY)
        rows = []
        row_no = 0

        for line in lines:
            row_no += 1
            ls = strip_line(line)

            # Item start  (skip !Sub "arn:aws....")
            p = ls.find(DELIM)
            q = ls.find('"')
            if p == -1 or (-1 < q < p):
                continue

            # Level
            level = len(line) - len(ls)

            # Item name, key, value
            if ls.endswith(DELIM):
                item_key = ls[0:-1]
                item_value = EMPTY
            else:
                item_key = ls[:p].lstrip('- ')
                item_value = ls[p + 1:].strip()

            # Add row
            rows.append([dir_name, file_name, row_no, EMPTY, EMPTY, level, item_key, item_value])
            continue
        return rows
