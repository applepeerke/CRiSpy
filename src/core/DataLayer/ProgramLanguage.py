# ---------------------------------------------------------------------------------------------------------------------
# ProgramLanguage.py
#
# Author      : Peter Heijligers
# Description : ProgramLanguage
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-03-12 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

EMPTY = ''


class ProgramLanguage(object):

    @property
    def file_ext(self):
        return self._file_ext

    @property
    def language_name(self):
        return self._language_name

    @property
    def may_have_security_headers(self):
        return self._may_have_security_headers

    def __init__(self,
                 file_ext,
                 framework_name,
                 may_have_security_headers=True,
                 ):
        self._may_have_security_headers = may_have_security_headers
        self._language_name = framework_name
        self._file_ext = file_ext
