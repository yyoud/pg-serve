"""
todo:
    -- create payload json from user id (provided via the auth process, where id is matched and password hashes compared)
    -- create
"""

from typing import Union
from json import dumps, loads
from base64 import urlsafe_b64encode as _url_b64e, urlsafe_b64decode as _url_b64d
from hashlib import algorithms_available as _alg
from hmac import new as _new


def assemble_payload(subject: Union[str, int], issued_at: int, expires: int):
    """
    assemble payload dictonary for JWT.
    find docs at `pg-serve/docs/SECURITY_ARCHITECTURE.md/#session-token`
    :param subject: user id, claimed from database via auth process
    :param issued_at: unix timestamp of assembly time (in seconds)
    :param expires: unix timestamp of expiration time (in seconds)
    :return: base-64 encoded payload dict in bytes
    """
    if not isinstance(subject, (str, int)) or not subject:
        raise TypeError("Invalid Subject.")

    if not isinstance(issued_at, int):
        raise TypeError("Invalid Issue Time.")

    if not isinstance(expires, int):
        raise TypeError("Invalid Expiration Time.")

    # stripping trailing chars will cause errors at decode time.
    return _url_b64e(dumps({"sub": subject, "iat": issued_at, "exp": expires}).encode())


def assemble_header(algorithm: str):
    """
    find docs at `pg-serve/docs/SECURITY_ARCHITECTURE.md/#session-token`
    :param algorithm: hash algorithm for payload signature
    :return: base-64 encoded header dict in bytes
    """
    if algorithm not in _alg or not isinstance(algorithm, str) or not algorithm:
        raise ValueError("Invalid Algorithm.")

    return _url_b64e(dumps({"alg": algorithm, "typ": "JWT"}).encode())


def sign_payload(header: bytes, payload: bytes, secret_key: bytes):
    alg = loads(_url_b64d(header))["alg"]

    # prevent silent errors from falling.
    if alg not in _alg or not isinstance(alg, str) or not alg:
        raise ValueError("Invalid Algorithm.")

    if not isinstance(secret_key, bytes):
        raise TypeError("Invalid Key Type.")

    if len(secret_key) != 32:
        raise ValueError("Invalid key.")

    msg = b".".join((_url_b64d(payload), _url_b64d(header)))
    return _url_b64e(_new(secret_key, msg, alg).digest())


def assemble_JWT(header: bytes, payload: bytes, signature: bytes):
    """
    assemble JWT token from parameters
    :param header: urlsafe base-64 encoded header.
    :param payload: urlsafe base-64 encoded payload.
    :param signature: urlsafe base-64 encoded signature of the payload.
    :return: token.
    """

    return b".".join((header, payload, signature))
