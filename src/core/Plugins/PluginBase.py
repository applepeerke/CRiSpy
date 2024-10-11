# ---------------------------------------------------------------------------------------------------------------------
# Sourcefile_Manager_Python.py
#
# Author      : Peter Heijligers
# Description : Build a call x-ref from a source file.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Enums import Color

log = Log()


class PluginBase:

    @property
    def messages(self):
        return self._messages

    @property
    def not_implemented_topics(self):
        return self._not_implemented_topics

    def __init__(self, scanner=None):
        self._scanner = scanner
        self._messages = []
        self._not_implemented_topics = set()
        self._session = Session()
        self._framework_name = None
        self._framework_name_prv = None
        self._frameworks = None

    def _plugin_log_result(self, topic):
        """ Process messages """
        indentation = 0

        if not self._framework_name:
            self._not_implemented_topics.add(topic)
            self._messages = []
            return

        log.new_line()
        log.stripe()
        if self._framework_name != self._framework_name_prv:
            self._framework_name_prv = self._framework_name
            log.add_coloured_line(f'{Color.GREEN}{self._framework_name}{Color.NC}')
            indentation += 2
        if not self._messages:
            self._not_implemented_topics.add(topic)
        else:
            log.add_coloured_line(f'{Color.GREEN}{topic}{Color.NC}', indentation=indentation)
            indentation += 2
            for m in self._messages:
                log.add_coloured_line(m.message, indentation=indentation)
        # For Unit test keep the messages
        if not self._session.unit_test:
            self._messages = []

    def _not_implemented(self):
        if not self._not_implemented_topics:
            return
        log.new_line()
        for topic in self._not_implemented_topics:
            if self._framework_name:
                log.add_coloured_line(
                    f"Topic '{Color.GREEN}{topic}{Color.NC}' has {Color.RED}not{Color.NC} (yet) been "
                    f'implemented for framework {self._framework_name}.', indentation=2)
            else:
                log.add_coloured_line(f"Unknown framework. Topic '{Color.GREEN}{topic}{Color.NC}' could "
                                      f'{Color.RED}not{Color.NC} be investigated.', indentation=2)
