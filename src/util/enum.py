#
#

from __future__ import annotations

from enum import Enum as _Enum


class PublicEndRequestType(_Enum):
    LOGIN = 'login'
    SIGNUP = 'signup'


class RequestScopes(_Enum):
    HEADER = 'header'
    BODY = 'body'
    QUERY = 'query'
