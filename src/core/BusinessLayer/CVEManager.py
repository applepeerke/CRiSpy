# ---------------------------------------------------------------------------------------------------------------------
# ExpressionManager.py
#
# Author      : Peter Heijligers
# Description : NIST CVE High and Medium vulnerabilities
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2023-03-08 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import json
import os
import threading
import urllib.request
from datetime import datetime
from datetime import timedelta
from os import listdir
from urllib.error import HTTPError

from src.core.DataLayer.CVEVulnerability import CVEVulnerability
from src.gl.BusinessLayer.ConfigManager import ConfigManager, CF_NIST_CVE_SYNC_LAST_DATE
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import EMPTY, CVE_CLI
from src.gl.Enums import ResultCode, MessageSeverity
from src.gl.Functions import loop_increment
from src.gl.GeneralException import GeneralException
from src.gl.Result import Result
from src.gl.Validate import normalize_dir, isInt

PGM = 'CVEManager'
csvm = CsvManager()
CM = ConfigManager()

year_p = 0
col_names = [
    'cve_id',
    'cve_published',
    'cve_last_modified',
    'severity',
    'criteria',
    'versionStartIncluding',
    'versionEndExcluding',
    'versionEndIncluding'
]


def blacklisted(criteria) -> bool:
    if 'firmware' in criteria:
        return True
    return False


def get_till_iso(now_iso) -> str:
    """
    For every of the 3-part processing, get the till_date.
    now_iso: For unit testing it may be in the past.
    Monthly processing starts at day 02, so till_date must then be 01.
    Daily processing ends at yesterday.
    """
    now_date = datetime.strptime(now_iso, "%Y-%m-%d")
    till_date_iso = now_iso \
        if now_iso[8:10] == '01' \
        else datetime.strftime(now_date - timedelta(1), '%Y-%m-%d')  # yesterday
    return till_date_iso


class CVEManager(object):

    @property
    def is_busy(self):
        return self._sync_process and self._sync_process.is_alive()

    @property
    def input_header_by_index(self):
        return self._input_header_by_index

    @property
    def input_header_by_name(self):
        return self._input_header_by_name

    @property
    def days_before_synchronized(self):
        return self._days_before_synchronized

    @property
    def months_synchronized(self):
        return self._months_synchronized

    @property
    def days_after_synchronized(self):
        return self._days_after_synchronized

    def __init__(self, check_only=True, test_sync_ymd=None, test_now_ymd=None, cli_mode=False):
        self._check_only = check_only
        self._cli_mode = cli_mode
        self._output_dir = normalize_dir(f'{Session().log_dir}Version_vulnerability', create=True)
        self._result = Result()
        self._sync_process = None
        self._input_header_by_index = {}
        self._input_header_by_name = {}
        self._days_before_synchronized = 0
        self._months_synchronized = 0
        self._days_after_synchronized = 0
        self._row_count = 0
        self._path = None
        self._rows = []
        self._filename_year: str = EMPTY
        self._now_iso = EMPTY
        self._from_iso = EMPTY
        self._to_01_date = EMPTY

        self._rows_count = 0
        self._PB = None
        self._PB_counter = 0
        self._installed_base_ids = {}
        self._threading = False
        # Unit test
        self._unit_test = test_sync_ymd or test_now_ymd
        self._from_ymd_test = test_sync_ymd
        self._now_ymd_test = test_now_ymd

    """
    Synchronize
    """

    def is_valid_installed_base(self) -> bool:
        """ Unit test. In reality only the most recent csv file should be validated """
        self._result = Result()
        try:
            paths = self._get_file_paths()
            for path in paths:
                self._validate_csv(path)
            return True
        except GeneralException:
            raise

    def synchronize(self) -> Result:
        check_only_save = self._check_only
        self._threading = False
        if self._do_synchronize():
            self._threading = True
            self._sync_process = threading.Thread(target=self._synchronize_thread, args=[check_only_save])
            self._sync_process.start()
        return self._result

    def _do_synchronize(self) -> bool:
        self._result = Result()
        # Already synced today?
        now_date = datetime.strftime(datetime.now(), '%Y-%m-%d')
        if CM.get_config_item(CF_NIST_CVE_SYNC_LAST_DATE) == now_date:
            self._result.add_message('CVE has already been synced today.')
            return False

        # Check what to do.
        self._synchronize_with_mode(check_only=True)

        # Something to do? (UT: don't go for real)
        if self._unit_test or (
                self._days_before_synchronized == 0 and
                self._months_synchronized == 0 and
                self._days_after_synchronized == 0):
            self._result.add_message('There is nothing to do.')
            return False

        # Ask for confirmation.
        if self._cli_mode:
            return True

        # - Prepare  message
        till_date_iso = get_till_iso(now_date)
        message = f'To synchronize from NIST\nfrom {self._from_iso} to {till_date_iso}:'
        if self._months_synchronized > 0:
            message = f'{message}\n  {self._months_synchronized} months'
        days = self._days_before_synchronized + self._days_after_synchronized
        if days > 0:
            message = f'{message}\n  {days} days'
            return True
        # - Ask
        # from src.UI.sg.General.Boxes import confirm
        # return confirm(f'{message}\n')

    def _synchronize_thread(self, check_only) -> Result:
        """ Thread. No UI actions here, Tkinter is not thread-safe. """
        days = self._days_before_synchronized + self._days_after_synchronized

        # Synchronize
        self._synchronize_with_mode(check_only=check_only)

        # Completion message
        if self._result.OK:
            now_date = datetime.strftime(datetime.now(), '%Y-%m-%d')
            CM.set_config_item(CF_NIST_CVE_SYNC_LAST_DATE, now_date)
            text_months = f'{self._months_synchronized} months and ' if self._months_synchronized > 0 else EMPTY
            self._result = Result(
                text=f'{text_months}{days} days are synchronized from NIST.\n'
                     f'{self._rows_count} rows are added to the csv files.', severity=MessageSeverity.Completion)
        return self._result

    def _get_confirm_text(self) -> str:
        message = f'To synchronize from NIST\nfrom {self._from_iso} to {self._to_iso}:'
        days = self._days_before_synchronized + self._days_after_synchronized
        if self._months_synchronized > 0:
            message = f'{message}\n  {self._months_synchronized} months'
        if days > 0:
            message = f'{message}\n  {days} days'
        return f'{message}\n'

    def _synchronize_with_mode(self, check_only=True):
        """
        Synchronize data from NIST.
        Sync_ymd and sync_now only for unit testing.
        """
        self._result = Result()
        self._check_only = check_only

        # Get from_date = the last synchronized date + 1 day
        self._from_iso = self._get_last_ymd_synchronized()
        date = datetime.strptime(self._from_iso, '%Y-%m-%d') + timedelta(1)
        self._from_iso = datetime.strftime(date, '%Y-%m-%d')  # 1 day later
        from_iso_work = self._from_iso

        from_ymd = datetime.strptime(self._from_ymd_test, '%Y-%m-%d') if self._unit_test \
            else datetime.strptime(from_iso_work, '%Y-%m-%d')
        # Get to_date = now (or a test date)
        to_ymd = datetime.strptime(self._now_ymd_test, '%Y-%m-%d') if self._unit_test \
            else datetime.now()
        self._to_iso = datetime.strftime(to_ymd, '%Y-%m-%d')
        to_iso_work = self._to_iso

        # a. Before months: If last synchronized day <> 01 (and in the past):
        #       Synchronize by days till 01 (if 01 in the past) or until yesterday.
        if from_iso_work[8:10] != '01' and to_ymd > from_ymd:
            to_01_date = self._add_1_month_to_day_01_iso(from_iso_work, to_iso_work)
            self._days_before_synchronized = \
                self._synchronize_by_days_till_yesterday_or_01(from_iso_work, to_01_date or to_iso_work)
            if check_only:
                from_iso_work = to_01_date or to_iso_work
            else:
                from_iso_work = self._get_last_ymd_synchronized()

        # b. Months: Synchronize months from 01 until 01 of this month.
        self._months_synchronized = self._synchronize_by_month(from_iso_work)
        if check_only:
            if self._months_synchronized > 0:
                from_iso_work = self._to_01_date
        else:
            from_iso_work = self._get_last_ymd_synchronized()

        # c. After months: Synchronize by days until yesterday.
        if self._months_synchronized > 0 \
                or from_iso_work != self._from_iso \
                or self._from_iso[8:10] == '01':
            self._days_after_synchronized = \
                self._synchronize_by_days_till_yesterday_or_01(from_iso_work, to_iso_work)

    def _synchronize_by_days_till_yesterday_or_01(self, from_iso, now_iso) -> int:
        if not from_iso or not now_iso:
            return 0
        # Determine till-date
        till_date_iso = get_till_iso(now_iso)
        till_date = self._add_days_iso(from_iso, till_date_iso=till_date_iso)
        # Synchronize
        days = self._synchronize_by_day(from_iso, till_date)
        # Output
        self._result.add_message(f'Synchronized with NIST from {from_iso} till {till_date}.')
        return days

    def _synchronize_by_day(self, from_date_iso, to_date_iso) -> int:
        """ synchronize data from NIST."""
        days = self._diff_days_iso(from_date_iso, to_date_iso)
        if days <= 0:
            return 0
        # Synchronize
        try:
            self._progress(days)
            self.get_cve_from_nist(from_date_iso, to_date_iso)
            return days
        except GeneralException:
            raise

    def _synchronize_by_month(self, from_iso) -> int:
        """ Always from day 01 to day 01 and in the past. """
        # Validation
        if from_iso[8:10] != '01':
            return 0
        # To date is now
        to_ymd = datetime.strptime(self._now_ymd_test, '%Y-%m-%d') if self._unit_test else datetime.now()
        to_iso = str(to_ymd.isoformat())[:10]
        # Get no. of months
        months = self._diff_months_iso(from_iso, to_iso)
        if months <= 0:
            return 0
        counter = 0
        # Go!
        try:
            # Synchronize per month
            # N.B. Not This month which may be incomplete still. Prevent duplicate rows.
            to_date_iso = self._add_1_month_to_day_01_iso(from_iso, to_iso)
            while to_date_iso and self._diff_months_iso(to_date_iso, to_iso) >= 0:
                counter += 1
                self._progress(counter * 30)
                # From date is a day later
                self.get_cve_from_nist(f'{from_iso[:7]}-02', to_date_iso)
                self._to_01_date = to_date_iso
                # Add a month
                from_iso = to_date_iso
                to_date_iso = self._add_1_month_to_day_01_iso(from_iso, to_iso)
            self._result.add_message(f'b. Synchronized with NIST from {from_iso} till {to_date_iso}.')
            return counter

        except GeneralException:
            raise

    def _progress(self, increment):
        if self._check_only or increment == 0 or self._threading:
            return
        # Initialize progress bar
        # if not self._PB and not self._cli_mode:
        #     days = self._days_after_synchronized + self._days_before_synchronized + (self._months_synchronized * 30)
        #     self._PB = ProgressMeter('Synchronize from NIST', count_max=days)
        #     self._PB_counter = 0
        # if self._PB and not self._PB.increment(increment):
        #     raise GeneralException('Canceled by the user.')

    def _get_last_ymd_synchronized(self) -> str:
        """
        Determine synchronization gap, from most recent CVE csv file.
        Installed base of CVE csv files is assumed to be validated.
        """
        # Unit test
        if self._unit_test:
            return self._from_ymd_test

        paths = self._get_file_paths()
        if not paths:
            raise GeneralException(f"Use '../utils/Get_all_CVE_from_NIST.py' first to retrieve baseline from NIST. "
                                   f'Place output folder {CVE_CLI} to output folder.')
        # First CVE.csv file is the most recent year
        path = paths[0]
        self._validate_csv(path)
        mmdd = str(self._get_last_mmdd_from_csv(path)).zfill(4)
        return f'{self._filename_year}-{mmdd[:2]}-{mmdd[2:]}'

    def _validate_csv(self, path):
        """ Check if CVE.csv is consistent. """
        self._initialize_csv(path)
        [self._validate_row(path, row) for row in self._rows]

    def _get_last_mmdd_from_csv(self, path) -> int:
        """ Get last existing yyyy-mm from csv file. """
        self._initialize_csv(path)
        return max(self._get_mmdd_from_valid_row(row) for row in self._rows if row)

    def _initialize_csv(self, path):
        self._row_count = 0
        self._rows = csvm.get_rows(include_header_row=True, data_path=path, include_empty_row=False)
        self._filename_year = os.path.basename(path)[:4]
        self._set_headers()
        self._rows = [row for row in self._rows[1:] if len(row) > 4 and row[0].startswith('CVE')]

    def _validate_row(self, path, row):
        self._row_count += 1
        postfix = f"Row_number={self._row_count}, row='{row}', path='{path}'."
        c_published = self._input_header_by_name['cve_published']
        year = row[c_published][:4]
        month = row[c_published][5:7]
        if not isInt(year) or not isInt(month):
            raise GeneralException(f'Invalid year {year} or month {month}. {postfix}')
        if year != self._filename_year:
            raise GeneralException(f'Expected year {self._filename_year} but got {year}. {postfix}')
        return

    def _get_mmdd_from_valid_row(self, row) -> int:
        c_published = self._input_header_by_name['cve_published']
        month = row[c_published][5:7]
        day = row[c_published][8:10]
        return int(month) * 100 + int(day)

    @staticmethod
    def _get_ymd_from_iso(iso_date: str) -> (int, int, int):
        """ Split iso date (str) in date parts (int) """
        try:
            _ = datetime.strptime(iso_date[:10], "%Y-%m-%d")
        except Exception:
            raise GeneralException(f"Invalid date '{iso_date}'")
        return int(iso_date[:4]), int(iso_date[5:7]), int(iso_date[8:10])

    @staticmethod
    def _add_days_iso(from_date_iso: str, till_date_iso: str) -> str:
        """ Adds a day till till-date reached. Returns in 'yyyy-mm-dd' format."""
        from_date = datetime.strptime(from_date_iso, "%Y-%m-%d")
        till_date = datetime.strptime(till_date_iso, "%Y-%m-%d")
        while from_date < till_date and loop_increment(f'{__name__}'):
            from_date = from_date + timedelta(1)
        return till_date.strftime("%Y-%m-%d")

    def _diff_months_iso(self, from_date: str, to_date: str) -> int:
        """ return: date difference in months, from 'yyyy-mm' dates """
        from_year, from_month, _ = self._get_ymd_from_iso(from_date)
        to_year, to_month, _ = self._get_ymd_from_iso(to_date)
        if to_year < from_year or (from_year == to_year and to_month < from_month):
            return 0
        return ((to_year - from_year) * 12) + (to_month - from_month)

    @staticmethod
    def _diff_days_iso(from_date: str, to_date: str) -> int:
        """ return: date difference in days, from 'yyyy-mm-dd' date. """
        diff = datetime.strptime(to_date, "%Y-%m-%d") - datetime.strptime(from_date, "%Y-%m-%d")
        return diff.days

    @staticmethod
    def _add_1_month_to_day_01_iso(from_iso, to_iso) -> str:
        """  Not in the future """
        year = int(from_iso[:4])
        month = int(from_iso[5:7])
        result = f'{year + 1}-01-01' if month == 12 else f'{year}-{str(month + 1).zfill(2)}-01'
        return result \
            if datetime.strptime(result, "%Y-%m-%d") < datetime.strptime(to_iso, "%Y-%m-%d") \
            else EMPTY

    """
    Get CVE installed base
    """

    def get_cve_from_nist(self, from_date_iso, to_date_iso, filtered=True, progress=False, version='2.0',
                          output_dir_suffix='CVE'):
        """
        Append to yyyy_CVE.csv.
        Input dates are in "yyyy-mm-dd" format, convert to timestamp yyyy-mm-ddT00:00:00.000
        url example:
        https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2023-01-01T00:00:00.000&pubEndDate=2023-01-02T00:00:00.000

        CVE structure:
            | vulnerabilities | # | 'cve' | ['id', 'configurations'] | # | 'nodes' | #
            |'cpeMatch' | '#' |  ['criteria', 'versionEndIncluding' ,...] |
        """
        output_dir = normalize_dir(f'{Session().output_dir}{output_dir_suffix}', create=True)
        output_dir = normalize_dir(f'{output_dir}{version}', create=True)
        if not output_dir:
            raise GeneralException(f"Invalid output directory '{output_dir}'")

        if progress:
            self._progress_cli(from_date_iso)

        # Unit test
        if self._check_only:
            self._from_ymd_test = to_date_iso
            return

        try:
            url = f'https://services.nvd.nist.gov/rest/json/cves/{version}/?pubStartDate={from_date_iso}' \
                  f'T00:00:00.000&pubEndDate={to_date_iso}T00:00:00.000'
            payload = urllib.request.urlopen(url)
        except HTTPError as e:
            self._result = Result(ResultCode.Error, f'HTTPError: {e}')
            return

        data = json.load(payload)

        # In "criteria" the package is listed.
        nist_rows = [col_names]
        vulnerabilities = data.get('vulnerabilities', [])
        for v in vulnerabilities:
            cve = v.get('cve')  # must exist
            cve_id = cve.get('id')
            cve_published = cve.get('published', EMPTY)
            cve_last_modified = cve.get('lastModified', EMPTY)
            description = self._get_description(cve.get('descriptions', []))
            severity = self._get_severity(cve.get('metrics', {}))
            if not severity:
                continue
            configurations = cve.get('configurations', [])
            for c in configurations:
                nodes = c.get('nodes')
                for n in nodes:
                    cpeMatch = n.get('cpeMatch')
                    for m in cpeMatch:
                        criteria = m.get('criteria')
                        vulnerable = m.get('vulnerable')
                        versionStartIncluding = m.get('versionStartIncluding', EMPTY)
                        versionEndIncluding = m.get('versionEndIncluding', EMPTY)
                        versionEndExcluding = m.get('versionEndExcluding', EMPTY)
                        if criteria and vulnerable and (
                                versionStartIncluding or versionEndExcluding or versionEndIncluding):
                            row = [cve_id, cve_published, cve_last_modified, severity, criteria, versionStartIncluding,
                                   versionEndExcluding, versionEndIncluding, description]
                            if filtered and blacklisted(criteria):
                                continue
                            nist_rows.append(row)

        # Append NIST rows to the csv of the year
        year = from_date_iso[:4]
        csv_path = f'{output_dir}{year}_{output_dir_suffix}.csv'
        exists = os.path.isfile(csv_path)

        # Filter duplicates
        nist_rows = self._filter_duplicates(nist_rows, csv_path, year)

        # No data (only a header)
        if len(nist_rows) == 1:
            print(f'\n*** All received NIST {len(vulnerabilities)} vulnerabilities '
                  f'from {from_date_iso} to {to_date_iso} are already processed ***')
            return

        # Write remaining rows
        CsvManager().write_rows(
            nist_rows[1:] if exists else nist_rows,
            data_path=csv_path,
            add_id=False,
            open_mode='a' if exists else 'w'
        )
        self._rows_count += len(nist_rows) - 1

    def _filter_duplicates(self, nist_rows, csv_path, year) -> list:
        # Get csv ids (per year)
        if year not in self._installed_base_ids:
            ids = {}
            if os.path.isfile(csv_path):
                rows = CsvManager().get_rows(data_path=csv_path, include_empty_row=False)
                ids = {f'{row[0]}|{row[1]}' for row in rows if row and len(row) > 2}
            self._installed_base_ids[year] = ids
        # Remove out-rows with existing ids
        return [row for row in nist_rows if len(row) > 2 and f'{row[0]}|{row[1]}' not in self._installed_base_ids[year]]

    @staticmethod
    def _get_description(descriptions) -> str:
        """ Only english """
        for d in descriptions:
            if d.get('lang', EMPTY) == 'en':
                return d.get('value', EMPTY)

    @staticmethod
    def _get_severity(metrics) -> str:
        """ Only HIGH and MEDIUM """
        result = EMPTY
        cvssMetricV31 = metrics.get('cvssMetricV31', [])
        for m in cvssMetricV31:
            cvssData = m.get('cvssData')
            severity = cvssData.get('baseSeverity', EMPTY)
            if severity == 'HIGH':
                return severity
            if severity == 'MEDIUM':
                result = severity
        return result

    @staticmethod
    def _progress_cli(from_date):
        global year_p
        year = from_date[:4]
        if year != year_p:
            print(f'{from_date[:7]}')
        else:
            print(f'     {from_date[5:7]}')
        year_p = year

    """
    Search
    """

    def search(self, product, company=EMPTY) -> [CVEVulnerability]:
        """ Search on company:product or :product: """
        if not product:
            return []
        vulnerabilities = []
        find_str = f':{company}:{product}:' if company else f':{product}:'
        for path in self._get_file_paths():
            # Get yyyy_CVE.csv rows
            self._rows = csvm.get_rows(include_header_row=True, data_path=path, include_empty_row=False)
            if not self._rows:
                continue
            # Set header definition
            self._set_headers()
            # Find product
            if not self._input_header_by_name.get('criteria'):
                raise GeneralException('NIST header does not contain "criteria"')
            colno = self._input_header_by_name['criteria']
            out_rows = []
            for i in range(len(self._rows)):
                if len(self._rows[i]) < colno:
                    print(f"row number {i} with content '{self._rows[i]}' is not valid. It is ignored.")
                    continue
                if find_str in self._rows[i][colno]:
                    out_rows.append(self._rows[i])
            self._write_vulnerabilities(product, out_rows)
            # Write findings
            vulnerabilities.extend([self._to_obj(row) for row in out_rows])
        return vulnerabilities

    def _write_vulnerabilities(self, product, rows):
        self._row_count += len(rows)
        dir_name = normalize_dir(f'{self._output_dir}CSV_vulnerabilities', create=True)
        path = f'{dir_name}CSV_vulnerabilities_for_{product}.csv'
        title = EMPTY if os.path.isfile(path) else self._input_header_by_name.keys()
        csvm.write_rows(
            rows,
            col_names=title,
            data_path=f'{dir_name}CSV_vulnerabilities_for_{product}.csv')

    def _to_obj(self, row) -> CVEVulnerability:
        return CVEVulnerability(
            cve_id=row[self._input_header_by_name['cve_id']],
            cve_published=row[self._input_header_by_name['cve_published']],
            cve_last_modified=row[self._input_header_by_name['cve_last_modified']],
            severity=row[self._input_header_by_name['severity']],
            criteria=row[self._input_header_by_name['criteria']],
            version_start_including=row[self._input_header_by_name['versionStartIncluding']],
            version_end_excluding=row[self._input_header_by_name['versionEndExcluding']],
            version_end_including=row[self._input_header_by_name['versionEndIncluding']],
            # description=row[self._input_header_by_name['description']],
        )

    """
    General
    """

    @staticmethod
    def _get_file_paths(version='2.0', suffix=CVE_CLI):
        """ Get CVE csv files already downloaded from NIST """
        CVE_dir = normalize_dir(f'{Session().output_dir}{suffix}')
        CVE_dir = normalize_dir(f'{CVE_dir}{version}')
        if os.path.isdir(CVE_dir):
            files = listdir(CVE_dir)
            return sorted([f'{CVE_dir}{f}' for f in files if f.endswith(f'_{suffix}.csv')], reverse=True)
        return []

    def _set_headers(self):
        header = self._rows[0]
        self._input_header_by_index = {i: header[i] for i in range(len(header))}
        self._input_header_by_name = {header[i]: i for i in range(len(header))}
