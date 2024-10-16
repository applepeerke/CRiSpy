FINDING = 'Finding'
FINDINGS = 'Findings'
SEARCH_PATTERNS = 'SearchPatterns'


class ImportFiles(object):
    BusinessRules = 'BusinessRules'


# Field definition
class FD(object):
    # SearchPatterns
    SP_Category_number = 'CategoryNo'
    SP_Category_name = 'CategoryName'
    SP_Category_value = 'CategoryValue'
    SP_Pattern = 'Pattern'
    SP_Pattern_name = 'PatternName'
    SP_Status = 'Status'
    SP_OutputFileName = 'OutputFileName'
    SP_Purpose = 'Purpose'
    SP_Search_only_for = 'SearchOnlyFor'
    SP_IncludeComment = 'IncludeComment'
    SP_NotInternetFacing = 'InternetFacing'
    SP_IncludeIfSingleThread = 'IncludeIfSingleThread'
    SP_Internal = 'Internal'
    SP_Apply_BRs = 'ApplyBRs'
    SP_Classification = 'Classification'
    SP_OWASP_2017 = 'OWASP_2017'
    SP_OWASP_2021 = 'OWASP'
    SP_Severity = 'Severity'
    SP_Details = 'Details'
    SP_Remediation = 'Remediation'
    SP_Ref_1 = 'Ref_1'
    SP_Ref_2 = 'Ref_2'

    # Findings
    FI_Pattern = 'Pattern'
    FI_Category_name = 'CategoryName'
    FI_Category_type = 'CategoryType'
    FI_Status = 'Status'
    FI_File_dir = 'FileDir'
    FI_File_name = 'FileName'
    FI_Line_no = 'LineNo'
    FI_Pos = 'Pos'
    FI_Source_line = 'SourceLine'
    FI_File_ext = 'FileExt'
    FI_Formatted_line = 'FormattedLine'
    FI_Index = 'Index'
    FI_File_name_ext = 'File_name_ext'

    # Reports
    EP_Path = 'Path'
    EP_Url = 'Url'
    EP_Method = 'Method'
    EP_Vulnerable = 'Vulnerable'
    EP_Sanitizer = 'Sanitizer'
    EP_Vulnerable_attributes = 'Vulnerable attributes'
    EP_Messages = 'Messages'

    CF_Dir_name = 'DirName'
    CF_File_name = 'FileName'
    CF_Type = 'Type'
    CF_Name = 'Name'
    CF_Items = 'Items'
    CF_Line_no = 'LineNo'
    CF_Level = 'Level'
    CF_Key = 'Key'
    CF_Value = 'Value'
    CF_Endpoint_uri = 'EndpointUri'
    CF_Http_method = 'HttpMethod'
    CF_Operation = 'Operation'


class CoreModel(object):

    @property
    def Finding(self):
        return self._Finding

    @Finding.setter
    def Finding(self, value):
        self._Finding = value

    @property
    def Findings(self):
        return self._Findings

    @Findings.setter
    def Findings(self, value):
        self._Findings = value

    def __init__(self):

        self._SearchPatterns = {
            1: FD.SP_Category_number,
            2: FD.SP_Category_name,
            3: FD.SP_Category_value,
            4: FD.SP_Pattern,
            5: FD.SP_Pattern_name,
            6: FD.SP_Status,
            7: FD.SP_OutputFileName,
            8: FD.SP_IncludeComment,
            9: FD.SP_NotInternetFacing,
            10: FD.SP_IncludeIfSingleThread,
            11: FD.SP_Internal,
            12: FD.SP_Apply_BRs,
            13: FD.SP_Purpose,
            14: FD.SP_Search_only_for,
            15: FD.SP_Classification,
            16: FD.SP_OWASP_2021,
            17: FD.SP_Severity,
            18: FD.SP_Details,
            19: FD.SP_Remediation,
            20: FD.SP_Ref_1,
            21: FD.SP_Ref_2
        }

        self._Finding = {
            0: FD.FI_Pattern,
            1: FD.FI_File_dir,
            2: FD.FI_File_name_ext,
            3: FD.FI_Line_no,
            4: FD.FI_Index,
            5: FD.FI_Source_line,
            6: FD.SP_Pattern_name,
            7: FD.SP_Purpose,
            8: FD.SP_Classification,
            9: FD.SP_OWASP_2021,
            10: FD.SP_Severity,
            11: FD.FI_File_ext,
            12: FD.FI_Formatted_line,
        }

        self._Findings = {
            1: FD.FI_Pattern,
            2: FD.FI_Category_name,
            3: FD.FI_Category_type,
            4: FD.FI_Status,
            5: FD.FI_File_dir,
            6: FD.FI_File_name,
            7: FD.FI_Line_no,
            8: FD.FI_Pos,
            9: FD.FI_Source_line,
            10: FD.SP_Pattern_name,
            11: FD.SP_Purpose,
            12: FD.SP_Classification,
            13: FD.SP_OWASP_2021,
            14: FD.SP_Severity,
            15: FD.FI_File_ext,
            16: FD.FI_Formatted_line
        }

        self._csvfiles = {
            FINDING: self._Finding,
            FINDINGS: self._Findings,
            SEARCH_PATTERNS: self._SearchPatterns
        }

    def get_att_names(self, file_name):
        """
        To get the headings (column names) in designed sequence
        :param file_name:
        :return:
        """
        att_names = []
        if file_name in self._csvfiles:
            for att in self._csvfiles[file_name].values():
                att_names.append(str(att).title())
        return att_names

    def get_att_dict(self, file_name):
        """
        To get the row numbers at the column names
        :param file_name:
        :return:
        """
        att_dict = {}
        if file_name in self._csvfiles:
            for key, att in self._csvfiles[file_name].items():
                att_dict[att] = int(key) - 1
        return att_dict

    def get_zero_based_column_number(self, file_name, col_name):
        """
        :return: 0-based row number
        """
        for col_number, att in self._csvfiles[file_name].items():
            if att == col_name:
                return int(col_number) - 1
        return -1
