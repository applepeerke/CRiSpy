# ---------------------------------------------------------------------------------------------------------------------
# PlugInManager_Python.py
#
# Author      : Peter Heijligers
# Description : Python plugin functions
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-07 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import os

from src.core.BusinessLayer.CVEManager import CVEManager
from src.core.DataLayer.CVEVulnerability import CVEVulnerability
from src.core.DataLayer.Enums import SecurityTopic
from src.core.Plugins.Functions import find_filename_from_parent_dir
from src.core.Plugins.PluginBase import PluginBase
from src.gl.BusinessLayer.CsvManager import CsvManager
from src.gl.Const import EMPTY, FALSE, TRUE
from src.gl.Enums import Color, MessageSeverity
from src.gl.Functions import soph_empty_list
from src.gl.Message import Message
from src.gl.Validate import normalize_dir, isInt

col_names = [
    'basename',
    'package',
    'version',
    'vulnerable',
    'cve_id',
    'versionStartIncluding',
    'versionEndExcluding',
    'versionEndIncluding',
    'reason',
    'description'
]


class VersionsBase(PluginBase):

    @property
    def versions_by_path(self):
        return self._versions_by_path

    @property
    def potential_vulnerable_rows(self):
        return self._version_output_rows

    @property
    def CVE_vulnerability_count(self):
        return self._CVE_vulnerability_count

    def __init__(self, scanner, cli_mode=False):
        super().__init__(scanner)
        self._output_dir = normalize_dir(f'{self._session.log_dir}Version_vulnerability', create=True)
        self._CVE_manager = CVEManager(self._output_dir, cli_mode=cli_mode)
        self._versions_by_path = {}
        self._versions_count = 0
        self._vulnerable_packages = set()
        self._CVE_vulnerability_count = 0
        self._version_output_rows = []

    def run(self, filename):
        self._versions_by_path = {p: {} for p in find_filename_from_parent_dir(filename)}

        # Add package versions (per path)
        [self._add_versions(filename, path) for path in self._versions_by_path]

        # Count all versions found
        self._versions_count = 0
        for path, packages in self._versions_by_path.items():
            self._versions_count += len(packages)

        # Search in CVE .csv files for vulnerabilities (per path per package version)
        self._search_in_CVE()

    def _add_versions(self, filename, path):
        """ Add package versions (per path) """
        raise NotImplementedError

    def _search_in_CVE(self):
        """
        Search in CVE .csv files for vulnerabilities (per path per package version)
        """

        # Get vulnerabilities per path
        count = 0

        for path in self._versions_by_path:
            basename = os.path.basename(path)
            for package, version in self._versions_by_path[path].items():
                # Progress
                count += 1
                # Add CVE vulnerabilities per package
                for vulnerability in self._CVE_manager.search(package):
                    self._add_vulnerable(basename, package, version, vulnerability)
                if package not in self._vulnerable_packages:
                    self._add_sane(basename, package, version)

        # Output
        self._write_findings(self._version_output_rows, f'{self._output_dir}Version_vulnerabilities.csv')
        self._completion_message()

    def _add_vulnerable(self, basename, package, version, v: CVEVulnerability):
        version_numbers = soph_empty_list(version.split('.'))
        cve_from = soph_empty_list(v.version_start_including.split('.'))
        cve_until = soph_empty_list(v.version_end_excluding.split('.'))
        cve_till = soph_empty_list(v.version_end_including.split('.'))

        # Optionally append '0' elements to version_numbers.
        while len(version_numbers) < max(len(cve_until), len(cve_till)):
            version_numbers.append('0')
        # Optionally append '0' elements to cve_from.
        while len(cve_from) < max(len(version_numbers), len(cve_until), len(cve_till)):
            cve_from.append('0')

        if len(version_numbers) < len(cve_from):
            self._add_row(basename, package, version, v, 'Unknown. Version elements < CVE version-start elements.')
        elif len(version_numbers) != len(cve_till) and len(version_numbers) != len(cve_until):
            self._add_row(basename, package, version, v,
                          'Unknown. Number of version elements differs from CVE version-end.')
        elif not cve_until and not cve_till:
            self._add_row(basename, package, version, v, f'Vulnerable, no end version')
        elif version and not all(isInt(n) for n in version_numbers):
            self._add_row(basename, package, version, v, f"Assumed vulnerable, incomparable '{version}'")
        elif cve_from and not all(isInt(n) for n in cve_from):
            self._add_row(basename, package, version, v,
                          f"Assumed vulnerable, incomparable '{v.version_start_including}'")
        elif cve_until and not all(isInt(n) for n in cve_until):
            self._add_row(basename, package, version, v,
                          f"Assumed vulnerable, incomparable '{v.version_end_excluding}'")
        elif cve_till and not all(isInt(n) for n in cve_till):
            self._add_row(basename, package, version, v,
                          f"Assumed vulnerable, incomparable '{v.version_end_including}")
        else:
            self._from_vulnerable, self._to_vulnerable = EMPTY, EMPTY
            [self._check_vulnerable(version_numbers, i, cve_from, cve_until, cve_till)
             for i in range(len(version_numbers))]
            # Equal from? Then vulnerable.
            self._check_from_equal(version_numbers, cve_from)
            # Between
            reason = 'Vulnerable' if self._from_vulnerable == TRUE and self._to_vulnerable == TRUE else EMPTY
            self._add_row(basename, package, version, v, reason)

    def _check_vulnerable(self, version: list, i: int, frm: list, until: list, till: list):
        """
        version: e.g.  1.0.2
        i: current element
        until = excluding date.
        till = including date.
        return: True if version element < CVE  element = vulnerable.
        """
        # Get the elements
        version_elem = version[i] if version else EMPTY
        cve_from = frm[i] if frm else EMPTY
        cve_until = until[i] if until else EMPTY
        cve_till = till[i] if till else EMPTY

        # a. Substitution
        #   No cve-from: vulnerable from the beginning
        if not frm:
            self._from_vulnerable = TRUE

        #   No cve-to: vulnerable to the end
        cve_to = cve_until if cve_until != EMPTY else cve_till
        if not until and not till:
            self._to_vulnerable = TRUE

        # b. Comparison
        #  As soon as a version element > from-CVE value, it is vulnerable v.v.
        if not self._from_vulnerable:
            if int(version_elem) > int(cve_from):
                self._from_vulnerable = TRUE
            elif int(version_elem) < int(cve_from):
                self._from_vulnerable = FALSE

        #  As soon as a version element > to-CVE value, it is NOT vulnerable v.v.
        if not self._to_vulnerable:
            if int(version_elem) > int(cve_to):
                self._to_vulnerable = FALSE
            elif int(version_elem) < int(cve_to):
                self._to_vulnerable = TRUE

    def _check_from_equal(self, version: list, frm: list):
        # From is vulnerable if all version numbers are equal to the cve_from numbers.
        if self._from_vulnerable or len(version) < len(frm):
            return
        if all(int(version[i]) == int(frm[i]) for i in range(len(frm))):
            self._from_vulnerable = TRUE

    def _add_row(self, basename, package, version, v: CVEVulnerability, reason):
        vulnerable = True if reason else False
        if vulnerable:
            self._vulnerable_packages.add(package)
            self._CVE_vulnerability_count += 1
        self._version_output_rows.append(
            [basename, package, version, vulnerable, v.CVE_id, v.version_start_including, v.version_end_including,
             v.version_end_excluding, reason, v.description])

    def _completion_message(self):
        suffix = ' vulnerabilities in the NIST CVE installed base.'
        vulnerable_count = len(self._version_output_rows)
        versions_found_text = f'{Color.GREEN}{self._versions_count}{Color.NC} packages with a version found. '
        if self._versions_count == 0:
            message = f'{Color.ORANGE}Warning{Color.NC}: {versions_found_text}'
        elif vulnerable_count == 0:
            message = f'{versions_found_text}There are {Color.GREEN}No{Color.NC}{suffix}'
        elif self._vulnerable_packages:
            message = f'{Color.RED}{list(self._vulnerable_packages)}{Color.NC} libraries have '
            f'{Color.RED}{self._CVE_vulnerability_count}{Color.NC}{suffix}.'
        else:
            message = f'There are {Color.GREEN}No{Color.NC}{suffix}'

        self._messages.append(Message(message, MessageSeverity.Completion))
        self._plugin_log_result(SecurityTopic.Configuration)

    @staticmethod
    def _write_findings(rows, path):
        if not rows:
            return
        CsvManager().write_rows(
            rows=rows,
            col_names=col_names,
            data_path=path,
            add_id=False)

    def _add_sane(self, basename, package, version):
        v = CVEVulnerability()
        reason = EMPTY
        self._version_output_rows.append(
            [basename, package, version, False, v.CVE_id, v.version_start_including, v.version_end_including,
             v.version_end_excluding, reason, v.description])
