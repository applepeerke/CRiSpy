from src.gl.Const import EMPTY, TRUE, FALSE
from src.gl.Enums import ResultCode, Color, MessageSeverity
from src.gl.Functions import loop_increment, find_files_in_path, strip_bytes_and_crlf, remove_surrounding_quotes, \
    remove_trailing_comment
from src.gl.Message import Message
from src.gl.Parse.Parser_Python import Parser_Python, EOF
from src.gl.Result import Result
from src.gl.Validate import toBool

PGM = 'SettingsAnalysis'

PASSWORD_POLICIES = 'password_policies'
SECURITY_MIDDLEWARE = 'security_middleware'
SESSION_MANAGEMENT = 'session_management'
WHITELIST_MIDDLEWARE = 'whitelist_middleware'


class SettingsAnalysis(object):
    def __init__(self):
        self._settings_paths = []
        self._settings_dict = {}
        self._parser = Parser_Python()

    @property
    def settings_paths(self):
        return self._settings_paths

    def set_settings_paths(self, django_manager):
        django_manager.get_settings()
        if django_manager.settings_module:
            # A. directory with settings
            self._settings_paths = find_files_in_path(django_manager.settings_module)
        elif django_manager.settings_path:
            # B. settings.py
            self._settings_paths.append(django_manager.settings_path)

    def settings_to_dict(self):
        """
        All UPPERCASE settings.py assignments to dict
        Last setting is preserved if there are more settings.py's
        """
        for path in self._settings_paths:
            # Read settings.py
            with open(path, 'rb') as f:
                rows = f.readlines()
            # Process settings.py rows
            target, source, delim_end = EMPTY, EMPTY, EMPTY
            for r in rows:
                r = strip_bytes_and_crlf(str(r))
                if not r:
                    continue  # Empty line
                # Assignment?
                p = r.find('=')
                if p > -1:
                    target = r[:p].strip()
                    if not target.isupper():
                        continue
                    source = r[p + 1:].lstrip()
                    # Block mode
                    if source in ('[', '{', '('):
                        delim_end = ']' if source == '[' else '}' if source == '{' else ')'
                    # Single line
                    else:
                        source = remove_trailing_comment(source)
                        source = remove_surrounding_quotes(source)
                        self._settings_dict[target] = source
                        continue
                # Block mode: add to block
                source = f'{source}{r}'
                # Block end
                if r == delim_end:
                    self._settings_dict[target] = source
                    continue

    def walk_settings_paths(self, subject) -> Message:

        """
        Return 1-line message after evaluating Settings.py snippets via a dynamic method
        """
        # Evaluate 1-n settings files, stop at 1st OK-one
        result = Result(ResultCode.Error, f'{PGM}: No {subject} found.')
        for path in self._settings_paths:
            if subject == PASSWORD_POLICIES:
                result = self.password_policies(path)
            elif subject == SECURITY_MIDDLEWARE:
                result = self.security_middleware(path)
            elif subject == SESSION_MANAGEMENT:
                result = self.session_management(path)
            elif subject == WHITELIST_MIDDLEWARE:
                result = self.whitelist_middleware(path)
            if result.code != ResultCode.Error:
                break
        message = result.text if result.OK \
            else f'{Color.RED}{result.text}{Color.NC}'
        return Message(message, MessageSeverity.Completion)

    def check_inline_settings(self, kv) -> [Message]:
        """
        Return 1-line message after parsing Settings.py snippets. Uses a dynamic method
        """
        messages = []
        for topic, method_name in kv.items():
            messages.extend(getattr(self, method_name)(topic))
        return messages

    def get_settings_snippets(self, find_string) -> dict:
        """ Return Settings.py snippets for the requested find-string """
        return {path: self._get_snippet(path, find_string) for path in self._settings_paths}

    def rest_framework(self, settings_path) -> Result:
        """
        REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("authz_middleware.rest_framework.authentication.AuthzAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("authz_middleware.rest_framework.permissions.IsAppWithoutUserAuthenticated",),}
        """
        expected_keys = ['DEFAULT_AUTHENTICATION_CLASSES', 'DEFAULT_PERMISSION_CLASSES']
        must_not_contain = ['Basic', 'Any']
        return self._get_block_result('Default authentication and authorization', settings_path, 'REST_FRAMEWORK',
                                      expected_keys, must_not_contain)

    def password_policies(self, settings_path) -> Result:
        """
    AUTH_PASSWORD_VALIDATORS = [
        {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
        {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
        {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
        {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    ]
        """
        policies = ['UserAttributeSimilarity', 'MinimumLength', 'CommonPassword', 'NumericPassword']
        return self._get_block_result('Password policies', settings_path, 'AUTH_PASSWORD_VALIDATORS', policies)

    def cookie_secure(self, topic) -> [Message]:
        messages = []
        # Precondition: cookie is used.
        k = f'{topic}_COOKIE_NAME'
        if not self._settings_dict.get(k):
            messages.append(self._get_message('Not found: ', MessageSeverity.Warning, k))

        k = f'{topic}_COOKIE_SECURE'
        settings_value = self._settings_dict.get(k)
        if not settings_value:
            messages.append(self._get_message('Not found: ', MessageSeverity.Warning, k))
        elif settings_value != TRUE:
            messages.append(self._get_message('Insecure: ', MessageSeverity.Error, k, settings_value))
        return messages

    def hsts(self, topic) -> [Message]:
        messages = []
        d = {'SECURE_HSTS_PRELOAD': TRUE,
             'SECURE_HSTS_SECONDS': '31536000',
             'SECURE_HSTS_INCLUDE_SUBDOMAINS': TRUE}
        for k, expected_value in d.items():
            settings_value = self._settings_dict.get(k)
            if not settings_value:
                messages.append(self._get_message(
                    'Not found: ', MessageSeverity.Warning, k))
            elif settings_value != expected_value:
                messages.append(self._get_message(
                    'Unexpected: ', MessageSeverity.Error, k, settings_value, expected_value))
        return messages

    @staticmethod
    def _get_message(text, severity, key, value=None, expected=None) -> Message:
        value_text = f"='{value}'{Color.NC}" if value else EMPTY
        expected_text = f". {Color.GREEN}Expected: {Color.NC}'{expected}'" if expected else EMPTY
        return Message(f"{Color.RED}{text}{Color.ORANGE}'{key}'{value_text}{expected_text}", severity)

    def session_management(self, settings_path) -> Result:
        """  N.B. Used via getattr(self, 'session_management') in walk_settings_paths. """

        prefix = f'{Color.GREEN}Settings.py{Color.NC} Session management: '
        result = Result(ResultCode.Error, f'{prefix}{Color.RED}Unknown{Color.NC}')

        installed_apps = self._get_snippet(settings_path, 'INSTALLED_APPS')
        session_storage = EMPTY
        if len([i for i in installed_apps if 'django.contrib.sessions' in i]) > 0:
            session_storage = 'Database backed'
        else:
            session_engine = self._get_snippet(settings_path, 'SESSION_ENGINE')
            if len([i for i in session_engine if 'backends.cached_db' in i]) > 0:
                session_storage = 'Persistent cache.'
            elif len([i for i in session_engine if 'backends.cache' in i]) > 0:
                session_storage = 'Non-persistent cache.'
            elif len([i for i in session_engine if 'backends.file' in i]) > 0:
                session_storage = 'File-based.'
            elif len([i for i in session_engine if 'backends.signed_cookies' in i]) > 0:
                session_storage = 'Cookie-based.'
        if session_storage:
            result = Result(ResultCode.Ok, f'{prefix}{Color.GREEN}{session_storage}{Color.NC}')
        return result

    def security_middleware(self, settings_path) -> Result:
        """  N.B. Used via getattr(self, 'security_middleware') in walk_settings_paths. """

        middleware_modules = [
            'SecurityMiddleware',
            'SessionMiddleware',
            'CsrfViewMiddleware',
            'AuthenticationMiddleware',
            'XFrameOptionsMiddleware'
        ]
        return self._get_block_result('Security middleware', settings_path, 'MIDDLEWARE', middleware_modules)

    def whitelist_middleware(self, settings_path) -> Result:
        """  N.B. Used via getattr(self, 'whitelist_middleware') in walk_settings_paths. """

        KPN_whitelist_settings = ['RANGES', 'PATH', 'NETWORKS']
        return self._get_block_result('KPN whitelist middleware', settings_path, 'WHITELIST_MIDDLEWARE',
                                      KPN_whitelist_settings)

    def _get_block_result(self, title, settings_path, find_string, expected, must_not_contain=None) -> Result:
        prefix = f'{Color.GREEN}Settings.py{Color.NC} {title}: '
        found = set()

        try:
            snippet = self._get_snippet(settings_path, find_string)
            for line in snippet:
                [found.add(exp) for exp in expected if exp in line]
            warnings = self._evaluate_snippet(snippet, must_not_contain)
            nf = [exp for exp in expected if exp and exp not in found]
            if warnings or nf:
                nf_text = ', '.join(nf) if nf else EMPTY
                warning_text = warnings if warnings else EMPTY
                return Result(
                    ResultCode.NotFound,
                    f"{prefix}{Color.RED}Not found: {Color.ORANGE}'{nf_text}{warning_text}'{Color.NC}")
            else:
                return Result(ResultCode.Ok, f'{prefix}{Color.GREEN}Complete{Color.NC}')
        except (OSError, IOError, IndexError) as e:
            return Result(ResultCode.Error, f"{PGM}._get_result '{title}' error: {e.args[1]} at '{settings_path}'")

    @staticmethod
    def _evaluate_snippet(snippet, must_not_contain) -> list:
        if not snippet or not must_not_contain:
            return []
        messages = []
        for line in snippet:
            for find_string in must_not_contain:
                if line.find(find_string) > -1:
                    messages.append(f"\n{Color.ORANGE}'{must_not_contain}'{Color.NC} found in '{line}'")
        return messages

    def _get_snippet(self, settings_path, find_string) -> list:
        with open(settings_path, 'rb') as fo:
            self._parser.read_line(fo)
            while self._parser.line != EOF and loop_increment(f'{__name__}'):
                if self._parser.get_next_elem(LC=False) == find_string:
                    return self._parser.get_this_snippet(fo)
                self._parser.read_line(fo)
        return []

    def is_true(self, find_string, if_not_exists: bool) -> bool:
        """ If no lines found, use default. If not all lines are the same, use default. """
        lines = self.get_lines(find_string)
        value = EMPTY
        for line in lines:
            if line.endswith(TRUE) and value in (EMPTY, TRUE):
                value = TRUE
            else:
                value = FALSE
        return if_not_exists if not value else toBool(value)

    def get_lines(self, find_string) -> list:
        """ Get list of 1 searched line in all Settings.py files """
        lines = [self._find_line(path, find_string) for path in self._settings_paths]
        return list(filter(None, lines))

    def _find_line(self, settings_path, find_string) -> str:
        """
        Example: 'DEFAULT_AUTHENTICATION_CLASSES': (
            'myDir.mySubdir.myClass',
            ),
        """
        found = False
        block_delims = {'(': ')', '{': '}', '[': ']'}
        out_line = EMPTY
        with open(settings_path, 'rb') as fo:
            self._parser.read_line(fo)
            while self._parser.line != EOF and loop_increment(f'{__name__}'):
                line = self._parser.line.rstrip()
                if line:
                    block_delim = line[-1]
                    if find_string in self._parser.line:
                        if block_delim not in block_delims:
                            return self._parser.line  # No delimiter
                        block_delim_start = block_delim
                        found = True
                    if found:
                        block_delim_end = line[-2] if len(line) > 1 and block_delim == ',' else block_delim
                        out_line = f'{out_line}{self._parser.line}'
                        if block_delim_end == block_delims[block_delim_start]:  # End delimiter found
                            return out_line
                self._parser.read_line(fo)
        return EMPTY
