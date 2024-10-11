#  ---------------------------------------------------------------------------------------------------------------------
# FrameworkManager.py
#
# Author      : Peter Heijligers
# Description : Manages Frameworks.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-17 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.core.BusinessLayer.Scanner import Scanner
from src.core.DataLayer.Enums import FrameworkName
from src.core.DataLayer.Framework import Framework
from src.core.DataLayer.SearchPattern import SearchPattern
from src.core.Plugins.Functions import find_filename_from_parent_dir
from src.core.Plugins.K8s.Functions import get_k8s_dir
from src.core.Plugins.Python.Frameworks.FastAPI.FastAPIManager import FastAPIManager
from src.core.Plugins.Python.Frameworks.Rest.RestManager import RestManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import ASTERISK
from src.gl.Enums import Output, Color
from src.gl.GeneralException import GeneralException
from src.gl.Parse.Parser_Python import Parser_Python

EMPTY = ''
parser = Parser_Python()

PGM = 'FrameworkManager'
RM = RestManager()
FastApiM = FastAPIManager()


class FrameworkManager:
    @property
    def frameworks(self):
        return self._frameworks

    @property
    def warnings(self):
        return self._warnings

    @property
    def scanner(self):
        return self._scanner

    def __init__(self):
        self._warnings = []
        self._scanner = None
        self._frameworks = {}
        self._synonyms = set()
        self._session = Session()

    def get_frameworks(self, file_extensions):
        """
        Get all supported frameworks (Django, SqlAlchemy, Marshmallow, FastApi, Scala)
        and Configurations (k8s, AWS policies, Maven)
        """
        if not file_extensions:
            raise GeneralException(f'{PGM}: No file extensions specified.')

        self._warnings = []
        self._frameworks = {}

        # Language frameworks
        [self._get_framework_findings_py(ext[1:]) for ext in file_extensions]

        # Configuration frameworks
        self.initialize_scanner()

        self._has_k8s_config()
        self._has_AWS_config()

        #  Java - Maven
        self._has_spring_config()

        #  .NET
        if '.cs' in file_extensions:
            self._add_framework(FrameworkName.NET)

    def has_framework(self, framework_name: FrameworkName) -> bool:
        return True if framework_name in self._frameworks else False

    def _get_framework_findings_py(self, file_type):
        if file_type != 'py':
            self._warnings.append(f"{PGM}: No frameworks are supported for language '{file_type}'")
            return

        self.initialize_scanner(file_type)

        if not self._has_django_model():
            self._has_rest_framework_model()
        self._has_sqlalchemy_model()
        self._has_marshmallow_model()
        self._has_fastapi_model()
        self._has_pydantic_model()

    def initialize_scanner(self, file_type=ASTERISK):
        self._scanner = Scanner(
            base_dir=self._session.input_dir,
            file_type=file_type,
            debug_path=self._session.debug_path)
        self._scanner.initialize_scan()

    def _has_rest_framework_model(self):
        if RM.is_framework(self._session, self._scanner):
            self._add_framework(FrameworkName.Rest)

    def _has_django_model(self) -> bool:
        models = None
        # Get paths to modules that import Django db.model
        # also django.solo SingletonModel and django_extensions.db.models
        if self._scanner.scan_dir(SearchPattern(pattern='django.'), output=Output.Object):
            if self._scanner.scan_dir(SearchPattern(pattern='django.db'), output=Output.Object):
                models = ['models.Model', 'SingletonModel', 'TimeStampedModel', 'ActivatorModel',
                          'TitleDescriptionModel', 'TitleSlugDescriptionModel']
            self._add_framework(FrameworkName.Django, models=models)
            return True
        return False

    def _has_sqlalchemy_model(self):
        # Get paths that use SqlAlchemy().Model or declarative_base()
        if not self._set_sqlalchemy_framework(FrameworkName.SQLAlchemy, '.Model'):
            self._set_sqlalchemy_framework('declarative_base', EMPTY)

    def _set_sqlalchemy_framework(self, find_string, model_suffix) -> bool:
        if not self._scanner.scan_dir(SearchPattern(pattern=f'{find_string}()'), output=Output.Object) \
                or len(self._scanner.findings) == 0:
            return False
        if len(self._scanner.findings) > 1:
            self._error(f'Framework {FrameworkName.SQLAlchemy} is ignored. Reason: Only 1 {find_string} '
                        f"model is supported. Otherwise the alias name (like 'db') cannot be determined. ")
            self._add_framework(FrameworkName.SQLAlchemy, models=None)
            return True

        # 1. Get db_name used (e.g. alias "db" from "db = SqlAlchemy()")
        line = self._scanner.findings[0].line
        var_name = parser.get_assignment_target(line) or f'{find_string}()'
        model_name = f'{var_name}{model_suffix}'
        pattern = f'({model_name})'

        # 2. Get paths using SqlAlchemy().Model or declarative_base()
        if self._scanner.scan_dir(SearchPattern(pattern=pattern), output=Output.Object):
            self._add_framework(FrameworkName.SQLAlchemy, models=[model_name])
        return True

    def _has_marshmallow_model(self):
        """ Look for " marshmallow" and " marshmallow_jsonapi" """
        self._scanner.scan_dir(SearchPattern(pattern=' marshmallow'), output=Output.Object)
        if self._scanner.findings:
            self._synonyms = set()
            [self._get_synonym(F.line, ' Schema ') for F in self._scanner.findings]
            self._add_framework(FrameworkName.Marshmallow, list(self._synonyms))

    def _has_pydantic_model(self):
        self._scanner.scan_dir(SearchPattern(pattern=' pydantic '), output=Output.Object)
        if self._scanner.findings:
            self._add_framework(FrameworkName.Pydantic, ['(BaseModel)', '(CamelModel)'])

    def _has_fastapi_model(self):
        self._scanner.scan_dir(SearchPattern(pattern=' fastapi '), output=Output.Object)
        if self._scanner.findings:
            self._add_framework(FrameworkName.FastApi)

    def _has_k8s_config(self):
        if get_k8s_dir(self._session.input_dir):
            # No findings needed yet.
            self._add_framework(FrameworkName.K8s)

    def _has_spring_config(self):
        if find_filename_from_parent_dir('pom.xml'):
            # No findings needed yet.
            self._add_framework(FrameworkName.Spring)

    def _has_AWS_config(self):
        if self._has_AWS_in('yaml') or self._has_AWS_in('json'):
            # No findings needed yet.
            self._add_framework(FrameworkName.AWS)

    def _has_AWS_in(self, file_type) -> bool:
        scanner = Scanner(base_dir=self._session.input_dir, file_type=file_type)
        return scanner.scan_dir(SearchPattern(pattern='aws:'), output=Output.Object)

    def _add_framework(self, framework_name, models=None):
        self._frameworks[framework_name] = Framework(
            name=framework_name,
            models=models,
            scanner=self._scanner)

    def _error(self, message):
        self._warnings.append(f'{PGM}: {Color.RED}{message}{Color.NC}')

    def _get_synonym(self, line, from_item):
        self._synonyms.add(f'({from_item.strip()})')
        if parser.find_and_set_pos(from_item, set_line=line, just_after=True):
            e = parser.get_next_elem()
            if e == 'as':
                self._synonyms.add(f'({parser.get_next_elem(LC=False)})')
