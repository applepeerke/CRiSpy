# ---------------------------------------------------------------------------------------------------------------------
# SecurityHeaders.py
#
# Author      : Peter Heijligers
# Description : Security header
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-09-17 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.Const import EMPTY


class SecurityHeaderResult(object):

    @property
    def allowed_values(self):
        return self._allowed_values

    @property
    def optional(self):
        return self._optional

    @property
    def found_values(self):
        return self._found_values

    @property
    def search_sources(self):
        return self._search_sources

    @property
    def found(self):
        return self._found

    @property
    def valid(self):
        return self._valid

    @property
    def line(self):
        return self._line

    # Setters

    @found.setter
    def found(self, value):
        self._found = value

    @valid.setter
    def valid(self, value):
        self._valid = value

    @line.setter
    def line(self, value):
        self._line = value

    def __init__(self, allowed_values, optional=False):
        self._optional = optional
        self._allowed_values = allowed_values
        self._search_sources = set()
        self._found_values = set()
        self._valid = False
        self._found = False
        self._line = EMPTY

    def add_source(self, source):
        self._search_sources.add(source)

    def add_found_value(self, value):
        self._found_values.add(value)

    def add_found_values_from_line(self, line):
        p = line.find(':') if line else -1
        if p > -1:
            values = line[p + 1:]
            for name in values.split(','):
                self.add_found_value(name.strip())


class Singleton:
    """ Singleton """

    class SecurityHeaders(object):
        OWASP_active_security_headers = [
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'Referrer-Policy',
            'X-Permitted-Cross-Domain-Policies',
            'Clear-Site-Data',
            'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy',
        ]

        @property
        def security_headers(self):
            return self._security_headers

        def __init__(self):
            self._security_headers = {
                'X-Content-Type-Options': SecurityHeaderResult(("nosniff",)),  # Before 'Content-Type'!"
                # 'X-Content-Type-Options': SecurityHeaderResult(("nosniff",)), # Before 'Content-Type'!
                # 'X-XSS-Protection': SecurityHeaderResult(('1',)),  deprecated
                'Content-Security-Policy': SecurityHeaderResult(('default-src',)),
                'Strict-Transport-Security': SecurityHeaderResult(('max-age=31536000',)),
                'X-Frame-Options': SecurityHeaderResult(('deny', 'sameorigin', 'allow-from')),
                'Referrer-Policy': SecurityHeaderResult(('no-referrer',)),
                'X-Permitted-Cross-Domain-Policies': SecurityHeaderResult(('none',), optional=True),
                'Clear-Site-Data': SecurityHeaderResult(('cache', 'cookies', 'storage'), optional=True),
                'Cross-Origin-Embedder-Policy': SecurityHeaderResult(('require-corp',), optional=True),
                'Cross-Origin-Opener-Policy': SecurityHeaderResult(('same-origin',), optional=True),
                'Cross-Origin-Resource-Policy': SecurityHeaderResult(('same-origin',), optional=True),
            }

        def set_header_from_line(self, line, source):
            for k, SHR in self._security_headers.items():
                if k in line:
                    SHR.add_source(source)
                    SHR.add_found_values_from_line(line)
                    SHR.found = True
                    if any(p.lower() in line.lower() for p in SHR.allowed_values):
                        if not SHR.valid:
                            SHR.valid = True
                            SHR.line = line
                    break

        def set_headers_from_k8s(self, more_set_headers):
            for line in more_set_headers:
                self.set_header_from_line(line, 'k8s')

    # ---------------------------------------------------------------------------------------------------------------------
    # Singleton logic
    # ---------------------------------------------------------------------------------------------------------------------

    # storage for the instance reference
    __instance = None

    def __init__(self):
        """ Create singleton instance """
        # Check whether we already have an instance
        if Singleton.__instance is None:
            # Create and remember instance
            Singleton.__instance = Singleton.SecurityHeaders()

        # Store instance reference as the only member in the handle
        self.__dict__['_Singleton__instance'] = Singleton.__instance

    def __getattr__(self, attr):
        """ Delegate access to implementation """
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        """ Delegate access to implementation """
        return setattr(self.__instance, attr, value)
