import datetime

from src.core.BusinessLayer.CVEManager import CVEManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import MODULE_DB
from src.gl.Validate import isInt

CVE_manager = CVEManager(check_only=False)


def main():
    to_year = datetime.datetime.now().year
    to_month = datetime.datetime.now().month
    from_year = to_year - 1
    _retrieve_all(from_year, to_year)
    _retrieve_all(to_year, to_year, to_month)


def _retrieve_all(from_year, to_year, month=0):
    """ Example: month 3 in 2023: from_year=2022, to_year=2023, month=3 """
    Session().set_paths(module_name=MODULE_DB)
    month_windows = [_get_month_windows_for_year(yyyy, month) for yyyy in range(to_year, from_year - 1, -1)]
    [CVE_manager.get_cve_from_nist(w[0][:10], w[1][:10], progress=True, output_dir_suffix='CVE_CLI')
     for y in month_windows for w in y]


def _get_month_windows_for_year(year, month=0):
    """ return: [[[2023-01-01T00:00:00.000], [2023-02-01T00:00:00.000]],...]"""
    if not isInt(year) or not isInt(month):
        return
    now = str(datetime.datetime.now().isoformat())[:-3]
    month_min = 1 if month == 0 else month
    month_max = 13 if month == 0 else month + 1
    month_windows = [
        [f'{format_date(year, m)}T00:00:00.000', f'{format_date(year, m + 1)}T00:00:00.000']
        for m in range(month_min, month_max)
        if f'{format_date(year, m + 1)}T00:00:00.000' <= now]
    return month_windows


def format_date(yyyy, mm):
    if mm == 13:
        mm = 1
        yyyy += 1
    return f'{yyyy}-{str(mm).zfill(2)}-01'


# ---------------------------------------------------------------------------------------------------------------------
# M a i n l i n e
# ---------------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    main()
