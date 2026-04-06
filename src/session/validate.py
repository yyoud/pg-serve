from __future__ import annotations

from util.exceptions import JWTError, SignatureError
from hmac import compare_digest as _compare_digest
from hashlib import algorithms_available as _alg
from json import loads
from base64 import b64decode as _b64d
from sign import sign_token
from time import time as _utcnow


async def validate_token(token: bytes, signing_key: bytes, *, blacklist: list[bytes] = None) -> bool | None:
    """
    Validate an issued JWT token.

    Errors risen:
      - JWTError -- Token attributes missing or are invalid (e.g. expired token) || Token blacklisted.
      - SignatureError -- Signature is invalid and/or corrupted.
      - SigningKeyError -- Signing key is invalid (risen inside the sign_token method).
      - TypeError -- Parameter types are invalid.

    :param token: issued JWT token.
    :param signing_key: signing key used to sign the token.
    :param blacklist: blacklisted JWT tokens, as a list of whole tokens packaged in base-64.
    :return: True if valid, None and raises errors otherwise.
    """
    if not isinstance(token, bytes):
        raise TypeError("Invalid token type.")

    if not len(token.split(b'.')) == 3:
        raise JWTError("Invalid token.")

    if not isinstance(signing_key, bytes):
        raise TypeError("Invalid signing key.")

    # check token in blacklist
    if blacklist and token in blacklist:
        raise JWTError("Blacklisted token.")

    header_raw: bytes = token.split(b'.')[0]
    payload_raw: bytes = token.split(b'.')[1]

    header: dict[str, str] = loads(_b64d(header_raw))
    payload: dict[str, int | str | float] = loads(_b64d(payload_raw))

    signature: bytes = _b64d(token.split(b'.')[2])

    # check header
    if not {'alg', 'typ'} <= header.keys() or header['alg'] not in _alg:
        raise JWTError("Invalid token.")

    if not header['typ'] == 'JWT':
        raise JWTError("Invalid token type.")

    # verify signature
    # signing key validation done inside the sign func
    temp = sign_token(header_raw, payload_raw, signing_key)

    if not _compare_digest(temp, signature):
        raise SignatureError("Invalid signature.")

    # verify exp date

    # 1. check keys exist at all
    if not {'exp', 'iat'} <= payload.keys():
        raise JWTError("Invalid token.")

    # 2. check valid key type
    if not isinstance(payload['exp'], float) or not isinstance(payload['iat'], float):
        raise JWTError("Invalid token.")


    # 3. check valid iat
    if payload['iat'] >= payload['exp'] or payload['iat'] > _utcnow():
        raise JWTError("Invalid or corrupt token.")

    if payload['exp'] <= _utcnow():
        raise JWTError("Expired token.")

    return True
