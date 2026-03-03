#
# find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#secret-key`
from typing import Union
import os as _os
from pathlib import Path as _Path
from base64 import urlsafe_b64decode as _url_b64d


class _SigningKeyProvider:
    def get_key(self, name: str) -> Union[bytes, None]:
        raise NotImplementedError


class EnvSigningKeyProvider(_SigningKeyProvider):
    def get_key(self, name: str) -> Union[bytes, None]:
        """
        find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#secret-key`
        :param name: Environment variable name of the secret key.
        :return: secret key.
        """
        if not isinstance(name, str) or not name:
            raise TypeError("Invalid Environment Variable Name.")

        key = _os.getenv(name)

        if not key:
            raise RuntimeError(f"Missing required environment variable: {name}")

        return key.encode()


class PEMSigningKeyProvider:
    def __init__(self, path: str):
        self.path = _Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Key file not found: {self.path}")

    def get_key(self) -> bytes:
        with self.path.open("rb") as f:
            pem_data = f.read()

        lines = pem_data.splitlines()
        body = b"".join(line for line in lines if not line.startswith(b"-----"))
        key_bytes = _url_b64d(body)
        return key_bytes


def provide_signing_key(var_name: str = None, path: str = None):
    """
    Provide global JWT signing key from an environment variable or a .PEM file
    :param path: Path name for .PEM file, full path recommended.
    :param var_name: Environment variable name of the secret key.
    :return: secret key.
    """

    if var_name and path:
        raise ValueError("Only one parameter should be provided.")

    if var_name:
        return EnvSigningKeyProvider().get_key(var_name)

    if path:
        return PEMSigningKeyProvider(path).get_key()
