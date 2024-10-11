# ---------------------------------------------------------------------------------------------------------------------
# SessionManager.py
#
# Author      : Peter Heijligers
# Description : Log all external links
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-11-01 PHe First creation

import os
import re

from src.core.DataLayer.CoreModel import CoreModel, FD
from src.gl.BusinessLayer.CsvManager import CsvManager as Csv_Manager
from src.gl.BusinessLayer.ErrorControl import ErrorType
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrorControl
from src.gl.GeneralException import GeneralException

csv_manager = Csv_Manager()
delimiting_tokens_end = [' ', '"', '\'', '(', ')', '\\', '[', ']']
delimiting_tokens_str = [' ', '"', '\'', '(', ')', '\\', '+', '=', '.', '[', ']']
links = set()
rows = []
str_pos = 0
EMPTY = ''
PGM = 'ExternalLinks.py'
PATTERN = '://'
MODEL_FINDINGS = 'Findings'


class ExternalLinks(object):

    def get_rows_with_external_links(self, inp_path, base_path=None, write_results=True) -> list:
        global links, rows

        if not os.path.isfile(inp_path):
            raise GeneralException(f"Input file does not exist: '{inp_path}'.")

        # Create file with distinct external links.

        # Get all "Findings.csv"-rows with pattern = "external parties".
        pattern_name_col = CoreModel().get_zero_based_column_number(MODEL_FINDINGS, FD.SP_Pattern_name)
        rows_with_external_links = csv_manager.get_row_set(
            {pattern_name_col: 'external_parties'}, inp_path, add_header_row=True)
        if len(rows_with_external_links) < 2:  # header row
            return []

        # Get column number of column "SourceLine" in Findings.csv
        source_line_col_number = CoreModel().get_zero_based_column_number(MODEL_FINDINGS, FD.FI_Source_line)
        if source_line_col_number < 0:
            ErrorControl().add_line(
                ErrorType.Error,
                PGM + ' reports: column ' + FD.FI_Source_line + ' not found in ' + MODEL_FINDINGS + '.')
            return []

        # Find all links and store them in a list
        # Replace "SourceLine" values with the formatted link
        links = set()
        for row in rows_with_external_links:
            row[source_line_col_number] = self._find_all_links_in_text(row[source_line_col_number])

        # *** deprecated *** Write rows to the "raw" file
        # csv_manager.write_rows(rows_with_external_links, open_mode='w', data_path=out_path1)

        # Write sorted links
        rows = sorted(list([link] for link in links)) if links else []
        if write_results:
            csv_manager.write_rows(rows, open_mode='w', data_path=f'{base_path}External_links.csv')
        return rows

    def _find_all_links_in_text(self, text):
        """
        Process all links in the text.
        :param text: 
        :return: input text, left trimmed at 1st link
        """
        global links, str_pos
        result = text

        indexes = [m.start() for m in re.finditer(PATTERN, text)]
        # While links found: add links
        for i in indexes:
            self._add_link(text, strpos=i)
            # First link found: store the link including all the rest.
            if len(links) == 1:
                result = text[indexes[0]:]
        # Return text starting at 1st link
        return result

    @staticmethod
    def _add_link(text, strpos):
        global links, str_pos
        str_pos = strpos
        # Left trim
        while str_pos > 0 and text[str_pos] not in delimiting_tokens_str:
            str_pos -= 1
        if text[str_pos] in delimiting_tokens_str:
            str_pos += 1

        # Find Link end
        text = text[str_pos:]
        end_pos = strpos - str_pos + len(PATTERN)  # end position = initial start position
        while end_pos < len(text) and text[end_pos] not in delimiting_tokens_end:
            end_pos += 1

        # Add the link
        if end_pos > 0:
            links.add(text[:end_pos])

    @staticmethod
    def _make_distinct(column) -> set:
        return set(cell for cell in column)
