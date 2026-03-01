#
# Native implementation of the PBKDF2 -> HKDF -> AEAD, DEK wrapping.
# found in docs: `databaseIntegratedUserInterface/userDataHandling/__init__.py/`

from __future__ import annotations

from os import urandom
from hashlib import pbkdf2_hmac as _pbkdf2
from cryptography.hazmat.primitives.ciphers.algorithms import AES as _AES
from cryptography.hazmat.primitives.ciphers.base import Cipher as _C
from cryptography.hazmat.primitives.ciphers.modes import GCM as _GCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives.hashes import SHA3_256 as _SHA3_256
from cryptography.hazmat.backends.openssl.backend import backend as _B


def S(P: bytes, B: bytes):  # PBKDF2 based secret derivation, through reliable secret `P`.
    """
    find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
    :param B: salt, required. must be at least 32 bytes.
    :param P: password to be asserted through row n
    :return: tuple[secret, salt] (salt is the same as inputted through parameters.)
    """
    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter Type.")

    if not isinstance(B, bytes):
        raise TypeError("Invalid Salt Type.")
    if not B or len(B) < 32:
        raise ValueError("Invalid Salt.")

    return _pbkdf2('sha3_256', password=P, salt=B, iterations=262144), B


# Table key serves as context binder, might add more in the DEK encryption stage or here, not sure yet.
# for now, there's enough context, since this system here sits after the auth and tokenization.
# noinspection PyShadowingNames
def rowRelativeHKDF(S: tuple[bytes, bytes], TableK: bytes, *, contextInfo: bytes = b""):
    """
        find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
        :param contextInfo: Optional additional context from primary key column row. asserted into HKDF.
        :param TableK: table key, context binder.
        :param S: row specific secret, derived from pbkdf2 of this protocol (above).
        :return: tuple[KEK, salt, TableK+contextInfo] (salt carried from S)
        """
    # Parameter Validation
    if not isinstance(S, tuple):
        raise TypeError("Invalid Secret Type.")

    if len(S) != 2:
        raise ValueError("Invalid Secret.")

    if not isinstance(TableK, (bytes, bytearray)):
        raise TypeError("Invalid Table Key Type.")

    if not TableK:
        raise ValueError("TableK must be non-empty bytes.")

    S1, S2 = S

    # HKDF
    T = _HKDF(_SHA3_256(), 32, S2, TableK+contextInfo, backend=_B).derive(S1)

    return T, S2, TableK+contextInfo  # salt and context preservation


def wrapDek(dek: bytes, KEK_HKDF: tuple[bytes, bytes, bytes]):
    """
    find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
    :param dek: random pre - generated dek
    :param KEK_HKDF: KEK, as a tuple composed in the HKDF function.
    :return: <wrappedDek>$<tag>$<nonce>$<salt> (salt carried from HKDF)
    """
    if not isinstance(KEK_HKDF, tuple):
        raise TypeError("Invalid HKDF Type.")

    if len(KEK_HKDF) != 3:
        raise ValueError("Invalid HKDF.")

    if len(dek) != 32:
        raise ValueError("Invalid DEK.")

    kek, B, AD = KEK_HKDF
    Q = urandom(12)  # nonce, generated each encryption session.

    cipherObj = _C(_AES(kek), _GCM(initialization_vector=Q), _B).encryptor()  # initialize

    cipherObj.authenticate_additional_data(AD)  # AAD

    wrappedDek = cipherObj.update(dek) + cipherObj.finalize()
    tag = cipherObj.tag

    # for now, returns as a `$` separated byte string for more compact DB assertion, though not optimal.
    return b'$'.join((wrappedDek, tag, Q, B))  # *important: preserve past random variables


# helper function
def constructKekFromPayload(P: bytes, wrappedDek: bytes, TableK: bytes, *, contextInfo: bytes = b""):
    if not isinstance(wrappedDek, bytes):
        raise TypeError("Invalid Data Encryption Key Type.")

    if len(wrappedDek.split(b"$")) != 4:
        raise ValueError("Invalid Data Encryption Key.")

    if not isinstance(TableK, (bytes, bytearray)):
        raise TypeError("Invalid Table Key Type.")

    if not TableK:
        raise ValueError("TableK must be non-empty bytes.")

    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter Type.")

    _, _, _, B = wrappedDek.split(b"$")

    return rowRelativeHKDF(S(P, B), TableK, contextInfo=contextInfo)


def unwrapDek(wrappedDek: bytes, KEK_HKDF: tuple[bytes, bytes, bytes]):
    """
    find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
    :param wrappedDek: wrapped dek with all its parameters, as
    :param KEK_HKDF: KEK, as a tuple composed in the HKDF function.
    :return: tuple[dek, salt] (original salt from S)
    """
    if not isinstance(wrappedDek, bytes):
        raise TypeError("Invalid Data Encryption Key Type.")

    if len(wrappedDek.split(b"$")) != 4:
        raise ValueError("Invalid Data Encryption Key.")

    wrappedDek, tag, nonce, salt = wrappedDek.split(b"$")

    kek, _, AD = KEK_HKDF

    cipherObj = _C(_AES(kek), _GCM(initialization_vector=nonce, tag=tag), _B).decryptor()

    cipherObj.authenticate_additional_data(AD)

    dek = cipherObj.update(wrappedDek) + cipherObj.finalize()

    return dek, salt
