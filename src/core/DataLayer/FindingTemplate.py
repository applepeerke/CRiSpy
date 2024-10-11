# ---------------------------------------------------------------------------------------------------------------------
# Finding.py
#
# Author      : Peter Heijligers
# Description : Validation functions
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2018-10-22 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.core.DataLayer.CoreModel import CoreModel, FD

model = CoreModel()

# Reports
FINDINGS = 'Findings'
REDOS = 'reDoS'
MODEL_FIELD_VALIDATIONS = 'Model - Field validations'
MODEL_WARNINGS = 'Warnings'
ENDPOINTS = 'Endpoints'
REST_FRAMEWORK_ENDPOINTS_DATA_FLOW = 'RestFramework endpoints data flow'

finding_templates = (
    FINDINGS, REDOS, MODEL_FIELD_VALIDATIONS, MODEL_WARNINGS, ENDPOINTS, REST_FRAMEWORK_ENDPOINTS_DATA_FLOW
)

template_headers = {
    FINDINGS: model.get_att_names(FINDINGS),
    REDOS: ['FileName', 'LineNo', 'StartPos', 'EndPos', 'Finding', 'DirName'],
    MODEL_FIELD_VALIDATIONS: [
        'Type', 'Title', 'Container', 'Input', 'Vulnerable', 'LineNo', 'Dir', 'File', 'Field', 'Type', 'ContainsId',
        'Length', 'SourceLine'],
    MODEL_WARNINGS: ['Warning'],
    ENDPOINTS: [FD.EP_Path, FD.EP_Url, FD.EP_Method, FD.EP_Vulnerable, FD.EP_Sanitizer, FD.EP_Vulnerable_attributes,
                FD.EP_Messages],
    REST_FRAMEWORK_ENDPOINTS_DATA_FLOW: [
        'ApiMethod', 'Class', 'Method', 'Parameter', 'Passed_to_methods_or_constructors', 'Returned_in_parameter',
        'LineNo', 'InputSerializer']
}
