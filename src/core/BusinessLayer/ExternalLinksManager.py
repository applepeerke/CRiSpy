# ---------------------------------------------------------------------------------------------------------------------
# FindingsManager.py
#
# Author      : Peter Heijligers
# Description : Consolidate all findings in a cross reference .csv file
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-07 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

from src.core.DataLayer.CoreModel import CoreModel
from src.core.BusinessLayer.FindingsManager import Singleton as Findings_Manager
from src.core.DataLayer import FindingTemplate
from src.gl.Const import FINDINGS_INTERNAL, EMPTY, CSV_EXT
from src.gl.Enums import Color
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.Validate import normalize_dir

PGM = 'ExternalLinksManager'
DATAFLOW = 'DataFlow'

model = CoreModel()
FM = Findings_Manager()


class ExternalLinksManager(object):
    """
    Find a string in specified file types in a base directory
    """

    def __init__(self, session):
        self._session = session

    def external_links(self) -> str:
        """
         Create Findings_internal.csv
         Findings.txt. files for internal use (e,g, External links) are parked in subfolder "Findings_internal".
         These are aggregated in the same way as in the parent folder.
         """
        if not self.is_input_valid(file_name=FINDINGS_INTERNAL):
            return EMPTY

        output_dir = normalize_dir(f'{self._session.log_dir}{FINDINGS_INTERNAL}', create=True)

        FM.initialize(FindingTemplate.FINDINGS, output_dir)
        findings_internal_path = f'{output_dir}{FINDINGS_INTERNAL}{CSV_EXT}'
        FM.aggregate_files(findings_internal_path)

        return findings_internal_path

    def is_input_valid(self, file_name) -> bool:
        if not self._session or not self._session.log_dir:
            Log().add_coloured_line(
                f'{Color.RED}ERROR{Color.NC}: '
                f'Could not create {file_name}.csv file. No session or output directory.')
            return False
        return True
