# ---------------------------------------------------------------------------------------------------------------------
# Decorators.py
#
# Author      : Peter Heijligers
# Description : RestFramework manager
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2021-08-18 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

PGM = 'Decorator'


class Decorator(object):
    @property
    def subject(self):
        return self._subject

    @property
    def decorator(self):
        return self._decorator

    @property
    def company_name(self):
        return self._company_name

    def __init__(self, subject, decorator, company_name=None):
        self._subject = subject
        self._decorator = decorator
        self._company_name = company_name
