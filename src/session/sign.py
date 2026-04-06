#
# find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#secret-key`
from typing import Union, Literal
import os as _os
from pathlib import Path as _Path
from base64 import b64decode as _b64d, b64encode as _b64e
from src.util.exceptions import SigningKeyError, JWTError
from hmac import new as _new
from hashlib import algorithms_available as _alg, new as _hashalg
from json import loads


class _SigningKeyProvider:
    def __init__(self, param: str):
        if not param or param == "":
            raise ValueError("Invalid Variable.")

        if not isinstance(param, str):
            raise TypeError("Invalid Variable Type.")

    def get_key(self) -> Union[bytes, None]:
        raise NotImplementedError

class EnvSigningKeyProvider(_SigningKeyProvider):
    def __init__(self, name: str):
        super().__init__(name)
        self._name = name

    def get_key(self) -> Union[bytes, None]:
        """
        find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#secret-key`
        :return: secret key.
        """
        key = _os.getenv(self._name)

        if not key:
            raise SigningKeyError(f"Missing required environment variable: {self._name}")

        return key.encode()


class PEMSigningKeyProvider(_SigningKeyProvider):
    def __init__(self, path: str):
        super().__init__(path)
        self.path = _Path(path)
        if not self.path.exists():
            raise SigningKeyError(f"Key file not found: {self.path}") from FileNotFoundError()

    def get_key(self, name: bytes = None) -> Union[bytes, None]:
        """
        find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#secret-key`

        :param name: name of key, if none the fetched key will be the first key in the file.
        :return: secret key as bytestring, decoded of base64.
        """

        with self.path.open("rb") as f:
            pem_data = f.read()

        lines = pem_data.splitlines()

        if name:
            body = b''
            idx = 0  # false
            for i, line in enumerate(lines):
                if line.startswith(b"-----BEGIN") and name in line:
                    idx = 1  # true
                    continue  # to the next line

                elif not line.startswith(b"-----") and idx:
                    body += line  # concatenate line

                elif line.startswith(b"-----END") and idx:
                    break

            if not idx:
                raise SigningKeyError(f"Missing key in pem file: {name}")

        else:
            body = b''
            for i, line in enumerate(lines):
                if line.startswith(b"-----BEGIN"):
                    continue

                elif not line.startswith(b"-----"):
                    body += line

                else:
                    break

        key_bytes = _b64d(body)
        return key_bytes


def provide_signing_key(value: str, provider: Literal["pem", "env"]):
    """
    Provide global JWT signing key from an environment variable or a .PEM file
    :param value: Path name for .PEM file or environment variable name.
    :param provider: type of provider. either "pem" or "env".
    :return: secret key.
    """

    if provider == "pem":
        return PEMSigningKeyProvider(value).get_key()  # value check occurs in obj init

    elif provider == "env":
        return EnvSigningKeyProvider(value).get_key()

    else:
        raise ValueError("Invalid provider.")


def sign_token(header: bytes, payload: bytes, secret_key: bytes):
    """
    Sign a JWT token.

    :param header: base-64 encoded header.
    :param payload: base-64 encoded payload.
    :param secret_key: bytestring secret key.

    :return: base-64 encoded signature.
    """
    header_data = loads(_b64d(header))

    if 'alg' not in header_data:
        raise JWTError("Invalid header.")

    alg = header_data["alg"]

    # prevent silent type errors from falling.
    if not(alg in _alg and isinstance(alg, str)):
        raise ValueError("Invalid Algorithm.")

    if not isinstance(secret_key, bytes):
        raise SigningKeyError("Invalid Key Type.") from TypeError()

    if len(secret_key) != _hashalg(alg).digest_size:
        raise SigningKeyError("Invalid key.") from ValueError()

    msg = b".".join((header, payload))  # remain b64 encoded
    return _b64e(_new(secret_key, msg, alg).digest())
