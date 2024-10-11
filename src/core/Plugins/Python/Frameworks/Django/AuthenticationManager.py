from src.core.DataLayer.Enums import FrameworkName
from src.core.Functions.FindProject import sophisticate_path_name
from src.core.Plugins.Const import AUTHC, AUTHZ, PERM
from src.core.Plugins.Python.Frameworks.Django.SettingsAnalysis import SettingsAnalysis
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.Config_constants import CF_COMPANY_NAME
from src.gl.Const import EMPTY
from src.gl.Enums import ResultCode, Color, MessageSeverity
from src.gl.Functions import loop_increment, path_leaf_only
from src.gl.Message import Message
from src.gl.Result import Result
from src.gl.BusinessLayer.SessionManager import Singleton as Session

PGM = 'AuthenticationManager'
CM = ConfigManager()


def set_color(text, apostroph=True):
    apo = '"' if apostroph else EMPTY
    return f'{Color.RED}None{Color.NC}' if not text else f'{Color.GREEN}{apo}{text}{apo}{Color.NC}'


class AuthenticationManager(object):

    @property
    def messages(self):
        return self._messages

    def __init__(self):
        self._company_name = CM.get_config_item(CF_COMPANY_NAME)
        self._session = Session()
        self._messages = []
        self._authentication_classes = set()
        self._RM = None

    def authentication_django(self, SA, RM):
        """
        STRIDE - Spoofing = Authentication
        """
        self._RM = RM
        # a.  DEFAULT_AUTHENTICATION_CLASSES from Settings.py
        title = 'DEFAULT_AUTHENTICATION_CLASSES'
        prefix = f'{Color.GREEN}  Settings: '
        self._get_default_authc_classes(SA, title)
        # Basic is not allowed
        for ac in self._authentication_classes:
            color = Color.RED if ac == 'Basic' else Color.BLUE
            self._messages.append(Message(
                f'{prefix}Default authentication class = {color}{ac}{Color.GREEN}.{Color.NC}',
                MessageSeverity.Completion))

        # Defined via authentication schemes (classes like Basic, Session, Token)
        # b. Is REST_FRAMEWORK active (KPN specific), from Settings.py?
        if self._company_name == 'KPN':
            django_authc = SA.is_true('AUTHZ_USE_DJANGO_AUTHENTICATION_MIDDLEWARE', if_not_exists=True)
            rfw_authc = SA.is_true('AUTHZ_USE_RESTFRAMEWORK_AUTHENTICATION', if_not_exists=True)
            if not django_authc and not rfw_authc:
                return Result(
                    ResultCode.Error,
                    f"{PGM} - 'AUTHZ_USE_xxx_AUTHENTICATION': No AUTHZ authentication found in Settings.py.")
            if not rfw_authc:
                return Result(
                    ResultCode.Error,
                    f"{PGM} - 'AUTHZ_USE_RESTFRAMEWORK_AUTHENTICATION': "
                    f'Rest_framework authentication has been set off in settings.')

            self._messages.append(Message(
                f'{prefix}{Color.BLUE}KPN AuthZ{Color.GREEN} authentication found.{Color.NC}',
                MessageSeverity.Completion))

    def _get_default_authc_classes(self, SA: SettingsAnalysis, title):
        """
        Example A:
            'DEFAULT_AUTHENTICATION_CLASSES': rest_framework.authentication.BasicAuthentication
        Example B:
            'DEFAULT_AUTHENTICATION_CLASSES': (
                'myDir.mySubdir.myClass',
                ),
        """
        # A
        find_string = 'rest_framework.authentication.'
        lines = SA.get_lines(title)
        found = False
        for line in lines:
            p = line.find(find_string, 0)
            while p >= 0 and loop_increment(f'{__name__}'):
                found = True
                s = p + len(find_string)
                q = line.find('Authentication', s)
                if q > -1:
                    self._authentication_classes.add(line[s:q])
                else:
                    self._authentication_classes.add(line[s:])
                    return  # Unexpected
                p = line.find(find_string, s)
        # B
        if not found:
            for line in lines:
                s1 = line.find('(')
                s2 = line.find('[')
                if s1 == s2 == -1:
                    return
                e = line.find(')') if s1 > -1 else line.find(']')
                class_name = line[s1 + 1:e] if s1 > -1 else line[s2 + 1:e]
                class_name = class_name.replace(',', EMPTY).replace('"', EMPTY).replace('\'', EMPTY)
                self._authentication_classes.add(class_name.strip())

    def authentication_endpoints(self, framework_name, endpoints, framework_decorators=None):
        self._messages.append(Message(f'\n    {Color.GREEN}Endpoints{Color.NC}', MessageSeverity.Completion))
        root_dir = f'{path_leaf_only(self._session.input_dir)}'

        for EP in endpoints.values():
            # Django and REST
            if framework_name in (FrameworkName.Django, FrameworkName.Rest):
                self._add_messages_django_and_rest(EP, root_dir, framework_decorators)
            # FastApi
            elif framework_name in (FrameworkName.FastApi, FrameworkName.Spring):
                self._add_messages_other(EP)
            else:
                pass

    def _add_messages_django_and_rest(self, EP, root_dir, framework_decorators):
        authc = ','.join(self._map_decorators(AUTHC, EP.authentication, EP.decorators, framework_decorators))
        perm = ','.join(self._map_decorators(PERM, EP.permission, EP.decorators, framework_decorators))
        authz = ','.join(self._map_decorators(AUTHZ, EP.authorization, EP.decorators, framework_decorators))
        authc_text = f'Authentication={set_color(authc)}'
        perm_text = f'Permission={set_color(perm)}'
        authz_text = f'Authorization={set_color(authz)}.'
        if EP.element.class_name or authc or authz:
            message = (Message(f'    {Color.BLUE}Endpoint{Color.NC} '
                               f'{Color.BLUE}class{Color.NC} {EP.element.class_name} '
                               f'{Color.BLUE}method{Color.NC} {EP.element.name} '
                               f'{Color.BLUE} has{Color.NC} {authc_text} '
                               f'{Color.BLUE}and{Color.NC} {perm_text} '
                               f'{Color.BLUE}and{Color.NC} {authz_text}'
                               f'{Color.BLUE}. Path={Color.NC}'
                               f'{sophisticate_path_name(EP.element.path, root_dir, EP.element.line_no)}',
                               MessageSeverity.Completion))
            self._messages.append(message)

    def _add_messages_other(self, EP):
        """
        a. FastApi framework
        Ex: '@app.get( path=f"{settings.BASE_PATH}/schema.json",
                dependencies=[Security(security.AuthZ().has_scopes(), scopes=["read_de_docs"])], )'
        b. Java Spring
        """
        self._authentication = EP.authentication
        self._authorization = EP.authorization
        self._add_authorization_from_decorators(EP.decorators)
        message = (Message(f'    {Color.BLUE}Endpoint{Color.NC} '
                           f'{Color.BLUE}route{Color.NC} {EP.route} '
                           f'{Color.BLUE}method{Color.NC} {EP.method_name or EP.element.name} '
                           f"{Color.BLUE}has Authentication={Color.NC}{set_color(','.join(list(self._authentication)))} "
                           f"{Color.BLUE}and Authorization={Color.NC}{set_color(','.join(list(self._authorization)))}"
                           f"{Color.BLUE}. Path={Color.NC}{EP.element.path.replace(self._session.input_dir, '../')} ",
                           MessageSeverity.Completion))
        self._messages.append(message)

    def _add_authorization_from_decorators(self, decorators):
        for decorator in decorators:
            if 'Security' in decorator:  # FastApi Security class
                s = decorator.find('scopes=[')
                if s > -1:
                    s += 8
                    e = decorator.find(']', s)
                    self._authorization.add(decorator[s:e])

    def _map_decorators(self, subject, endpoint_values, decorators, framework_decorators) -> list:
        """
        Add every framework-supported decorator that occurs in the endpoint to the EP definition.
        """
        if not decorators:
            return endpoint_values
        #
        for decorator in decorators:
            for D in framework_decorators:
                if (not D.company_name or D.company_name == self._company_name) \
                        and D.subject == subject \
                        and decorator.startswith(D.decorator):
                    endpoint_values.add(decorator)
        return endpoint_values
