# ---------------------------------------------------------------------------------------------------------------------
# AWS_Policy.py
#
# Author      : Peter Heijligers
# Description : AWS Policy
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-07-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.Const import EMPTY


class AWS_Policy(object):

    def __init__(self,
                 topic=None,
                 sid=None,
                 ID=None,
                 statement=None,
                 resource: list = None,
                 principal: list = None,
                 effect=EMPTY,
                 ):
        self._topic = topic
        self._sid = sid
        self._ID = ID
        self._statement = statement
        self._resource = resource if resource else []
        self._principal = principal if principal else []
        self._effect = effect

    @property
    def topic(self):
        return self._topic

    @property
    def sid(self):
        return self._sid

    @property
    def ID(self):
        return self._ID

    @property
    def statement(self):
        return self._statement

    @property
    def resource(self):
        return self._resource

    @property
    def principal(self):
        return self._principal

    @property
    def effect(self):
        return self._effect

    # Setters
    @topic.setter
    def topic(self, value):
        self._topic = value

    @sid.setter
    def sid(self, value):
        self._sid = value

    @ID.setter
    def ID(self, value):
        self._ID = value

    @statement.setter
    def statement(self, value):
        self._statement = value

    @principal.setter
    def principal(self, value):
        self._principal = value

    @resource.setter
    def resource(self, value):
        self._resource = value

    @effect.setter
    def effect(self, value):
        self._effect = value
