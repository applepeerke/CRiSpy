import os

from fastapi import APIRouter, Response, HTTPException, Query
from starlette import status

from src.api.services.crisp.model import LineModel
from src.api.services.functions import get_latest_result_folder, get_txt_as_lines, get_filename_from_prefix
from src.core.BusinessLayer.ExternalLinksManager import DATAFLOW
from src.core.DataLayer.FindingTemplate import ENDPOINTS, MODEL_FIELD_VALIDATIONS
from src.core.Functions.Functions import get_csv_as_html, get_csv_as_txt
from src.gl.BusinessLayer.ConfigManager import ConfigManager, get_desc
from src.gl.BusinessLayer.Config_constants import *
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.Const import FINDINGS, CSV_EXT, EMPTY
from src.gl.Enums import ApplicationTypeEnum, ExecTypeEnum

crisp = APIRouter()
crisp_custom_pattern_search = APIRouter()

crisp_findings = APIRouter()
crisp_endpoints = APIRouter()
crisp_input_validation = APIRouter()
crisp_log = APIRouter()

crisp_parameters = APIRouter()

log = Log()
CM = ConfigManager()
CM.start_config()


@crisp_custom_pattern_search.get('/custom_search_pattern')
async def custom_pattern_search(
        input_dir: str = Query(
            CM.get_config_item(CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR)),  # query parameter
        custom_pattern: str = Query(
            CM.get_config_item(CF_CUSTOM_SEARCH_PATTERN), description=get_desc(CF_CUSTOM_SEARCH_PATTERN))
):
    # To prevent running CRiSp in the normal way, do an extra check.
    if not custom_pattern:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail='A search pattern is required.')
    from src.core.BusinessLayer.CRiSpy import CRiSpy
    kwargs = get_kwargs()
    kwargs['input_dir'] = input_dir
    kwargs['custom_search_pattern'] = custom_pattern
    crispy_pgm = CRiSpy(**kwargs)
    result = crispy_pgm.start()
    if not result.OK:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get_text())
    return Response(status_code=status.HTTP_200_OK)


@crisp.get('/crisp', response_model=LineModel)
async def start_crisp(
        input_dir: str = Query(
            CM.get_config_item(
                CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR)),  # query parameter
        application_type: ApplicationTypeEnum = Query(
            CM.get_config_item(
                CF_APPLICATION_TYPE) or ApplicationTypeEnum.Any, description=get_desc(CF_APPLICATION_TYPE)),  # dropdown
        exec_type: ExecTypeEnum = Query(
            CM.get_config_item(
                CF_EXEC_TYPE) or ExecTypeEnum.Both, description=get_desc(CF_EXEC_TYPE)),  # dropdown

):
    from src.core.BusinessLayer.CRiSpy import CRiSpy
    kwargs = get_kwargs()
    kwargs['input_dir'] = input_dir
    kwargs['project_name'] = None  # Must be auto-determined
    kwargs['custom_search_pattern'] = None
    kwargs['application_type'] = application_type or ApplicationTypeEnum.Any  # May be empty
    kwargs['exec_type'] = exec_type or ExecTypeEnum.Both  # May be empty
    crispy_pgm = CRiSpy(**kwargs)
    result = crispy_pgm.start()
    if not result.OK:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get_text())
    return {"lines": log.get_log()}


@crisp_log.get('/log', response_model=LineModel)
async def get_log(
        input_dir: str = Query(CM.get_config_item(CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR))):
    most_recent_dir_name = get_latest_result_folder(input_dir)
    return {"lines": get_txt_as_lines(os.path.join(most_recent_dir_name, 'Log.txt'))}


@crisp_findings.get('/findings')
async def get_findings(
        input_dir: str = Query(CM.get_config_item(CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR))):
    return get_html_response_from_csv(input_dir, f'{FINDINGS}.csv', FINDINGS)


@crisp_endpoints.get('/endpoints')
async def get_endpoints(
        input_dir: str = Query(CM.get_config_item(CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR))):
    most_recent_dir_name = get_latest_result_folder(input_dir)
    if not most_recent_dir_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No valid CRiSp output subdirectory has been found for the specified input folder.")
    file_name = get_filename_from_prefix(most_recent_dir_name, ENDPOINTS, DATAFLOW)
    if not file_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No valid {ENDPOINTS} file was found in subfolder {DATAFLOW} of the CRiSp output folder.")
    return get_html_response_from_csv(input_dir, file_name, DATAFLOW)


@crisp_input_validation.get('/input_validation')
async def get_input_validation(
        input_dir: str = Query(CM.get_config_item(CF_INPUT_DIR), description=get_desc(CF_INPUT_DIR))):
    return get_html_response_from_csv(input_dir, f'{MODEL_FIELD_VALIDATIONS}{CSV_EXT}', DATAFLOW)


def get_json_response_from_csv(input_dir, filename, subdir=None) -> dict:
    if not input_dir or not filename:
        return {}
    path = _get_file_path(input_dir, filename, subdir)
    return {"lines": get_csv_as_txt(path)}


def get_html_response_from_csv(input_dir, filename, subdir=None) -> str:
    if not input_dir or not filename:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No input directory or no filename has been specified.")
    path = _get_file_path(input_dir, filename, subdir)
    return get_csv_as_html(path)


def _get_file_path(input_dir, filename, subdir=None) -> str:
    most_recent_dir_name = get_latest_result_folder(input_dir)
    if not most_recent_dir_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No CRiSp results are found for the specified input folder. Has CRiSp run?")
    path = os.path.join(most_recent_dir_name, filename) if not subdir \
        else os.path.join(most_recent_dir_name, subdir, filename)
    return path if os.path.isfile(path) else EMPTY


@crisp_parameters.put('/parameters')
async def set_parameters(
        company_name=CM.get_config_item(CF_COMPANY_NAME),
        output_dir=CM.get_config_item(CF_OUTPUT_DIR),
        data_dir=CM.get_config_item(CF_DATA_DIR),
        log_title=CM.get_config_item(CF_LOG_TITLE),
        verbose=CM.get_config_item(CF_VERBOSE),
        filter_findings=CM.get_config_item(CF_FILTER_FINDINGS),
        quick_scan=CM.get_config_item(CF_QUICK_SCAN),
        synchronize_cve=CM.get_config_item(CF_SYNC_CVE),
        output_type=CM.get_config_item(CF_OUTPUT_TYPE),
        exec_time_threshold_ms=CM.get_config_item(CF_TIME_EXEC_LOG_THRESHOLD_MS),
        exec_time_max_s=CM.get_config_item(CF_TIME_EXEC_MAX_S)
):
    CM.set_config_item(CF_COMPANY_NAME, company_name)
    CM.set_config_item(CF_OUTPUT_DIR, output_dir)
    CM.set_config_item(CF_DATA_DIR, data_dir)
    CM.set_config_item(CF_LOG_TITLE, log_title)
    CM.set_config_item(CF_VERBOSE, verbose)
    CM.set_config_item(CF_FILTER_FINDINGS, filter_findings)
    CM.set_config_item(CF_QUICK_SCAN, quick_scan)
    CM.set_config_item(CF_SYNC_CVE, synchronize_cve)
    CM.set_config_item(CF_OUTPUT_TYPE, output_type)
    CM.set_config_item(CF_TIME_EXEC_LOG_THRESHOLD_MS, exec_time_threshold_ms)
    CM.set_config_item(CF_TIME_EXEC_MAX_S, exec_time_max_s)
    CM.write_config()
    return Response(status_code=status.HTTP_200_OK)


def get_kwargs() -> dict:
    return {
        'input_dir': CM.get_config_item(CF_INPUT_DIR),
        'application_type': CM.get_config_item(CF_APPLICATION_TYPE),
        'log_title': CM.get_config_item(CF_LOG_TITLE),
        'company_name': CM.get_config_item(CF_COMPANY_NAME),
        'custom_search_pattern': CM.get_config_item(CF_CUSTOM_SEARCH_PATTERN),
        'verbose': CM.get_config_item(CF_VERBOSE),
        'filter_findings': CM.get_config_item(CF_FILTER_FINDINGS),
        'quick_scan': CM.get_config_item(CF_QUICK_SCAN),
        'synchronize_cve': CM.get_config_item(CF_SYNC_CVE),
        'output_type': CM.get_config_item(CF_OUTPUT_TYPE),
        'output_dir': CM.get_config_item(CF_OUTPUT_DIR),
        'data_dir': CM.get_config_item(CF_DATA_DIR),
        'project_name': CM.get_config_item(CF_PROJECT_NAME),
        'exec_type': CM.get_config_item(CF_EXEC_TYPE),
        'excluded_dir_names': CM.get_config_item(CF_SPECIFIED_EXCLUDED_DIR_NAMES),
        'excluded_file_names': CM.get_config_item(CF_SPECIFIED_EXCLUDED_FILE_NAMES),
        'sane_if_pattern_in': CM.get_config_item(CF_SPECIFIED_SANE_IF_PATTERN_IN),
        'time_exec_threshold_ms': CM.get_config_item(CF_TIME_EXEC_LOG_THRESHOLD_MS),
        'time_exec_max_ms': CM.get_config_item(CF_TIME_EXEC_MAX_S),
        'debug_path': CM.get_config_item(CF_DEBUG_PATH),
        'debug_pattern_name': CM.get_config_item(CF_DEBUG_PATTERN_NAME),
    }
