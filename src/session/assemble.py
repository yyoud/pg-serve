"""
todo:
    -- embed kek into tokens (still make it optional for the sake of abstraction)
    -- develop kek encryption mechanism
"""

from typing import Union
from json import dumps
from base64 import b64encode as _b64e
from hashlib import algorithms_available as _alg
from time import time as _utcnow

from session.sign import sign_token
from util.exceptions import JWTError, SigningKeyError


def issue_token(leap: float, subject: str | int, signing_key: bytes, *,
                algorithm: str = 'sha256',
                payload_attrs: dict[str, str | float | int]=None,
                header_attrs: dict[str, str | float | int] = None):
    """
    issue a token at current time, expires at ``current_time + leap_time``.
    :param leap: leap time in seconds.
    :param signing_key: bytestring signing key for signature.
    :param subject: user primary identifier, claimed from database via auth process.
    :param algorithm: hash algorithm for signature digest.
    :param payload_attrs: payload additional attributes.
    :param header_attrs: header additional attributes.
    :return: fully assembled token as bytes
    """
    if not isinstance(leap, (int, float)):
        raise JWTError("Invalid Leap Time.") from TypeError()

    if not isinstance(signing_key, bytes):
        raise SigningKeyError("Invalid Signing Key.") from TypeError()

    header = assemble_header(algorithm, **(header_attrs or {}))
    now = _utcnow()
    payload = assemble_payload(subject, now, now+leap, **(payload_attrs or {}))
    return assemble_JWT(header, payload, signing_key)


# noinspection DuplicatedCode
def assemble_payload(subject: Union[str, int], issued_at: float, expires: float, **kwargs: dict[str, str | float | int]):
    """
    assemble payload dictionary for JWT.
    find docs at `pg-serve/docs/SECURITY_ARCHITECTURE.md/#session-token`
    :param subject: user id, claimed from database via auth process
    :param issued_at: unix timestamp of assembly time (in seconds)
    :param expires: unix timestamp of expiration time (in seconds)
    :return: base-64 encoded payload dict in bytes
    """
    if not isinstance(subject, (str, int)) or not subject:
        raise TypeError("Invalid Subject.")

    if not isinstance(issued_at, (int, float)):
        raise TypeError("Invalid Issue Time.")

    if not isinstance(expires, (int, float)):
        raise TypeError("Invalid Expiration Time.")

    payload_raw = {"sub": subject, "iat": issued_at, "exp": expires}

    if kwargs and kwargs.keys().isdisjoint(payload_raw.keys()):  # kwargs doesnt contain already existing attrs
        for k, v in kwargs.items():
            if not isinstance(v, (int, float, str)):
                raise JWTError(f"Invalid Header Attribute {k}.") from TypeError()
            payload_raw[k] = v

    # stripping trailing chars will cause errors at decode time.
    return _b64e(dumps(payload_raw).encode())


# noinspection DuplicatedCode
def assemble_header(algorithm: str, **kwargs: dict[str, str | float | int]):
    """
    find docs at `pg-serve/docs/SECURITY_ARCHITECTURE.md/#session-token`
    :param algorithm: hash algorithm for payload signature
    :return: base-64 encoded header dict in bytes
    """
    if algorithm not in _alg or not isinstance(algorithm, str) or not algorithm:
        raise ValueError("Invalid Algorithm.")

    header_raw = {"alg": algorithm, "typ": "JWT"}

    if kwargs and kwargs.keys().isdisjoint(header_raw.keys()):
        for k, v in kwargs.items():
            if not isinstance(v, (int, float, str)):
                raise JWTError(f"Invalid Header Attribute {k}.") from TypeError()
            header_raw[k] = v


    return _b64e(dumps(header_raw).encode())


def assemble_JWT(header: bytes, payload: bytes, signing_key: bytes):
    """
    assemble JWT token from parameters

    :param header: base-64 encoded header.
    :param payload: base-64 encoded payload.
    :param signing_key: bytestring signing key.

    :return: assembled token as bytes.
    """

    signature = sign_token(header, payload, signing_key)

    return b".".join((header, payload, signature))
