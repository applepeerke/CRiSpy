# ---------------------------------------------------------------------------------------------------------------------
# SearchPatternManager.py
#
# Author      : Peter Heijligers
# Description : Manage SearchPattern.csv
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import csv

from src.core.DataLayer.CoreModel import CoreModel, FD
from src.core.DataLayer.Enums import NotInternetFacing
from src.core.DataLayer.SearchPattern import SearchPattern
from src.gl.BusinessLayer.ErrorControl import ErrorType
from src.gl.BusinessLayer.ErrorControl import Singleton as ErrCtl
from src.gl.BusinessLayer.LogManager import Singleton
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import CSV_SEARCH_PATTERNS, EMPTY, MODEL_SEARCH_PATTERNS, CATEGORY_LANGUAGE, CATEGORY_COMPANY, \
    CATEGORY_GENERAL, ALL, NONE
from src.gl.Enums import ApplicationTypeEnum
from src.gl.Functions import is_internet_facing
from src.gl.GeneralException import GeneralException

model = CoreModel()


class SearchPatternManager(object):
    """
    Manage the business data in .csv files
    """

    def __init__(self):
        self._search_patterns = []
        self._selections = {}
        c_category_name = model.get_zero_based_column_number(MODEL_SEARCH_PATTERNS, FD.SP_Category_name)
        c_category_type = model.get_zero_based_column_number(MODEL_SEARCH_PATTERNS, FD.SP_Category_value)
        self._selection_cols = [c_category_name, c_category_type]
        self._log = Singleton()
        self._sp_att_dict = CoreModel().get_att_dict('SearchPatterns')
        self._pattern_names = set()
        self._all_pattern_name_dict = {}
        self._valid_pattern_name_dict = {}
        self._total_pattern_count = 0
        self._pattern_counts_per_category_dict = {}

    @property
    def search_patterns(self):
        return self._search_patterns

    @property
    def selections(self):
        return self._selections

    @property
    def total_pattern_count(self):
        return self._total_pattern_count

    @property
    def pattern_counts_per_category_dict(self):
        return self._pattern_counts_per_category_dict

    @property
    def pattern_names(self):
        return self._pattern_names

    @property
    def all_pattern_name_dict(self):
        return self._all_pattern_name_dict

    @property
    def valid_pattern_name_dict(self):
        return self._valid_pattern_name_dict

    @valid_pattern_name_dict.setter
    def valid_pattern_name_dict(self, value):
        self._valid_pattern_name_dict = value

    def get_valid_search_patterns(
            self, data_path=None, one_pattern_name=None, application_type: ApplicationTypeEnum = None,
            languages: list = None,
            companies=None, general=True, category_name=None) -> list:
        """
        Get SearchPatterns from csv file rows.
        You may apply 0-n row selections.
        A selection is 'Passed' when the specified column contains the specified value, or is empty.
        :param data_path: Needed for unit test.
        :param one_pattern_name: 1-pattern mode
        :param application_type: selections pattern per app type
        :param languages: list of Category languages to add to searchpatterns. None=All.
        :param companies: Category patterns matching Company to add to searchpatterns. None=All.
        :param general: Unittest purpose. By default included.
        :param category_name: One of (General, Language, Company) of which the set of patterns is to be returned.
        :return: SearchPattern list
        """
        # Get all search patterns
        if not self.set_all_patterns(data_path):
            return []

        # Construct a selection on Category list
        self._selections = {
            CATEGORY_LANGUAGE: languages or [NONE],
            CATEGORY_COMPANY: companies or [ALL],
            CATEGORY_GENERAL: [ALL] if general is True else [NONE]
        }
        # Pattern counts
        self._pattern_names = set()
        self._total_pattern_count = 0
        self._pattern_counts_per_category_dict = {
            CATEGORY_GENERAL: 0,
            CATEGORY_LANGUAGE: 0,
            CATEGORY_COMPANY: 0
        }
        # Get the search pattern rows from crisp_data.csv,
        search_patterns = []

        # Search pattern rows | Example:
        # ------------------------------
        # 0 = No                54
        # 1 = Category name     Language
        # 2 = Category value    Java
        # 3 = Pattern value     non-Crap
        # 4 = Pattern name      nonCrap
        # 5 = Action            investigate
        # 6 = OutputFolderName  investigate
        # 7 = OutputFileName    Language_Java_nonCrap

        for sp in self._search_patterns:
            self._total_pattern_count += 1
            # Count patterns per category
            self._pattern_counts_per_category_dict[sp.category_name] += 1
            self._pattern_names.add(sp.pattern_name)

            # 1-pattern mode, get it from the list
            if one_pattern_name:
                valid = sp.pattern_name.lower() == one_pattern_name.lower()
            # All-pattern mode
            else:
                # A. Only a set of 1 category name (e.g. Company) is wanted
                if category_name:
                    valid = sp.category_name == category_name
                else:
                    # B. Optional selections in OR-relation.
                    # Read selected category values, if one is valid this is okay.
                    valid = False
                    for category, values in self._selections.items():
                        # In Unit test none of this category may be selected.
                        if values != [NONE] and self._is_matching_item(sp, category, values):
                            valid = True
            # Exclude:
            if application_type and not one_pattern_name:
                # Concurrency patterns in a single-threaded code base.
                if application_type == ApplicationTypeEnum.Standalone \
                        and not sp.include_if_single_thread:
                    valid = False
                # Frontend patterns in a not-internet-facing code base.
                elif not is_internet_facing(application_type) \
                        and sp.not_internet_facing == NotInternetFacing.Exclude:
                    valid = False

            # Evaluate
            if valid:
                search_patterns.append(sp)
                self._valid_pattern_name_dict[sp.pattern_name] = sp
                # One pattern found: EXIT
                if one_pattern_name and sp.pattern_name.lower() == one_pattern_name.lower():
                    break

        return search_patterns

    def set_all_patterns(self, data_path=None) -> bool:
        self._search_patterns = []
        self._all_pattern_name_dict = {}

        if not data_path:
            if not Session() or not Session().import_dir:
                ErrCtl().add_line(ErrorType.Error, 'Invalid session. No search patterns available.')
                return False
            data_path = f'{Session().import_dir}{CSV_SEARCH_PATTERNS}'

        first = True
        try:
            with open(data_path) as csvFile:
                data_reader = csv.reader(csvFile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for row in data_reader:
                    if first:
                        first = False
                        continue
                    sp = SearchPattern(
                        pattern=row[self._sp_att_dict[FD.SP_Pattern]],
                        pattern_name=row[self._sp_att_dict[FD.SP_Pattern_name]],
                        status=row[self._sp_att_dict[FD.SP_Status]],
                        output_subfolder_name=row[self._sp_att_dict[FD.SP_Status]],
                        category_name=row[self._sp_att_dict[FD.SP_Category_name]],
                        category_value=row[self._sp_att_dict[FD.SP_Category_value]],
                        include_comment=row[self._sp_att_dict[FD.SP_IncludeComment]],
                        not_internet_facing=row[self._sp_att_dict[FD.SP_NotInternetFacing]],
                        include_if_single_thread=row[self._sp_att_dict[FD.SP_IncludeIfSingleThread]],
                        internal=row[self._sp_att_dict[FD.SP_Internal]],
                        apply_business_rules=row[self._sp_att_dict[FD.SP_Apply_BRs]],
                        purpose=row[self._sp_att_dict[FD.SP_Purpose]],
                        search_only_for=row[self._sp_att_dict[FD.SP_Search_only_for]],
                        OWASP=row[self._sp_att_dict[FD.SP_OWASP_2021]],
                        classification=row[self._sp_att_dict[FD.SP_Classification]],
                        severity=row[self._sp_att_dict[FD.SP_Severity]],
                        remediation=row[self._sp_att_dict[FD.SP_Remediation]],
                        details=row[self._sp_att_dict[FD.SP_Details]],
                        ref_1=row[self._sp_att_dict[FD.SP_Ref_1]],
                        ref_2=row[self._sp_att_dict[FD.SP_Ref_2]],
                    )
                    self._search_patterns.append(sp)
                    self._all_pattern_name_dict[sp.pattern_name] = sp
            return True
        except (IOError, Exception) as e:
            raise GeneralException(f'SearchPatternManager exception: {e}')

    def _initialize_valid_patterns_dict(self):
        if not self._valid_pattern_name_dict:
            self.get_valid_search_patterns()

    def _is_matching_item(self, sp: SearchPattern, selection_key, select_values):
        category_name = sp.category_name
        category_value = EMPTY
        cols_qty = len(self._selection_cols)

        if cols_qty > 1:
            category_value = sp.category_value

        # Category_name does not match: next filter.
        if category_name != selection_key:
            return False

        # Category_name matches. If
        #  - only Category_name is selected, or
        #  - (one of the) selection value(s) is "All", or
        #  - Category_name is empty:
        #      Passed!
        if cols_qty == 1 or category_value == EMPTY or select_values == [ALL]:
            return True

        # If Category_value is one of the specified ones: Passed!
        for select_value in select_values:
            if select_value == category_value:
                return True
        return False

    def get_category_name_set(self, category_name) -> set:
        """
        Return a selection set of category types for a specified category name.
        Categories are listed in SearchPatterns.csv as [name, type].
        :param category_name:
        :return: category types set
        """
        # 1. Set selection to ALL types for the specified category Name (General, Company or Language).
        self._selections = {category_name: EMPTY}

        # 2. Set the column number of the category Name
        # 3. Get the search patterns for the specified category name
        patterns = self.get_valid_search_patterns(category_name=category_name)

        # 4. Return unique set of category types.
        return set(pattern.category_value for pattern in patterns)

    def get_valid_pattern_names(self) -> list:
        return [p.pattern_name for p in self.get_valid_search_patterns()]

    def get_valid_pattern_names_dict(self) -> dict:
        self._initialize_valid_patterns_dict()
        return self.valid_pattern_name_dict

    def get_valid_pattern(self, pattern_name) -> SearchPattern:
        self._initialize_valid_patterns_dict()
        return self.valid_pattern_name_dict.get(pattern_name)

    def copy_valid_pattern(
            self, from_name, to_name, default: SearchPattern, category_name=EMPTY, purpose=EMPTY) -> SearchPattern:
        self._initialize_valid_patterns_dict()
        SP = self.get_valid_pattern(from_name) or default
        if SP:
            SP.category_name = category_name
            SP.pattern_name = to_name
            SP.purpose = purpose
        return SP
