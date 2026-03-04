#
# Service-specific exceptions

from typing import Optional


class _BaseException(Exception):
    def __init__(self, msg: Optional[str]):
        super().__init__(msg)


class SigningKeyError(_BaseException):
    """
    Used for errors arising while trying to load JWT signing keys.
    """
    def __init__(self, msg: Optional[str]):
        base_message = 'JWT Signing-key Error: ' + (msg or '') + ';'

        if not msg:
            base_message.replace(':', '')
        super().__init__(base_message)


class AuthError(_BaseException):
    def __init__(self, msg: Optional[str]):
        base_message = 'Authentication Error: ' + (msg or '') + ';'
        super().__init__(base_message)
