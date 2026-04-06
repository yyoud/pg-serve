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
    def __init__(self, msg: Optional[str] = None):
        base_message = (msg or '') + ';'

        if not msg:
            base_message = base_message.replace(':', '')

        super().__init__(base_message)


class SignatureError(_BaseException):
    """
    Used for errors while verifying JWT signatures.
    """
    def __init__(self, msg: Optional[str] = None):
        base_message = 'Signature Error: ' + (msg or '') + ';'

        if not msg:
            base_message = base_message.replace(':', '')
        super().__init__(base_message)


class AuthError(_BaseException):
    def __init__(self, msg: Optional[str] = None):
        base_message = 'Authentication Error: ' + (msg or '') + ';'

        if not msg:
            base_message = base_message.replace(':', '')
        super().__init__(base_message)


class JWTError(_BaseException):
    def __init__(self, msg: Optional[str] = None):
        base_message = 'JWT Error: ' + (msg or '') + ';'

        if not msg:
             base_message = base_message.replace(':', '')
        super().__init__(base_message)


class ServerError(_BaseException):
    def __init__(self, msg: Optional[str] = None):
        base_message = 'Server Error: ' + (msg or '') + ';'

        if not msg:
            base_message = base_message.replace(':', '')
        super().__init__(base_message)
