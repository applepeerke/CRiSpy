from src.core.DataLayer.CoreModel import FD
from src.gl.GeneralException import GeneralException

PGM = 'CoreReport'


class CoreReport(object):
    ConfigFile = 'Config_File'
    Endpoints = 'Endpoints'

    def __init__(self, report_name):
        self._report_name = report_name

    Names = [ConfigFile, Endpoints]

    Defs = {
        ConfigFile: {
            1: FD.CF_Dir_name,
            2: FD.CF_File_name,
            3: FD.CF_Line_no,
            4: FD.CF_Type,
            5: FD.CF_Name,
            6: FD.CF_Level,
            7: FD.CF_Key,
            8: FD.CF_Value,
        },
        Endpoints: {
            1: FD.CF_Dir_name,
            2: FD.CF_File_name,
            3: FD.CF_Line_no,
            4: FD.CF_Type,
            5: FD.CF_Name,
            6: FD.CF_Level,
            7: FD.CF_Key,
            8: FD.CF_Value,
        }
    }

    @staticmethod
    def get_header(report_name) -> list:
        return [att.name for att in CoreReport.Defs[report_name].values() if report_name not in CoreReport.Defs]

    @staticmethod
    def _map_report_names_to_atts_dict(report_name) -> dict:
        """ Map report definition attribute names to Attributes. """
        return {att.name: att for att in CoreReport.Defs[report_name].values() if report_name in CoreReport.Defs}

    def map_header_to_0_based_colno_dict(self, report_name, header: list) -> dict:
        """ Map row header column names to column numbers. """
        d = {}
        def_d = self._map_report_names_to_atts_dict(report_name)
        for i in range(len(header)):
            name = header[i]
            if not name:
                raise GeneralException(
                    f"{PGM}: Column heading {i + 1} is empty in rows for report '{report_name}'")
            # header column name MUST exist in report definition.
            if name not in def_d:
                raise GeneralException(
                    f"{PGM}: Column heading '{name}' is not defined in '{report_name}'")
            else:
                d[name] = i
        return d
