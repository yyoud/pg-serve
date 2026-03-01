"""
todo:
    implement encryption and decryption functions for bytes data which uses normal aes256
"""

from __future__ import annotations

from os import urandom
from cryptography.hazmat.primitives.ciphers.algorithms import AES as _AES
from cryptography.hazmat.primitives.ciphers.base import Cipher as _C
from cryptography.hazmat.primitives.ciphers.modes import GCM as _GCM
from cryptography.hazmat.backends.openssl.backend import backend as _B


def encryptData(DEK: bytes, D: bytes):
    """
    Encrypts bytestring data using a dek (or really any 32 byte key)
    :param DEK: a key of size 32 bytes
    :param D: plaintext data.
    :return: encrypted data in format tuple[ciphertext, tag, nonce]
    """
    if not isinstance(DEK, bytes):
        raise TypeError("Invalid Key Type.")
    if len(DEK) != 32:
        raise ValueError("Invalid Key.")

    if not isinstance(D, bytes):
        raise TypeError("Invalid Data Type.")

    Q = urandom(12)  # nonce, generated each encryption session.

    cipherObj = _C(_AES(DEK), _GCM(initialization_vector=Q), _B).encryptor()  # initialize

    ciphertext = cipherObj.update(D) + cipherObj.finalize()
    tag = cipherObj.tag
    return ciphertext, tag, Q


def decryptData(DEK: bytes, D: tuple[bytes, bytes, bytes]):
    """
    Decrypts encrypted data from format tuple[ciphertext, tag, nonce]
    :param DEK: a key of size 32 bytes
    :param D: encrypted data in format tuple[ciphertext, tag, nonce]
    :return: plaintext
    """

    if not isinstance(DEK, bytes):
        raise TypeError("Invalid Key Type.")
    if len(DEK) != 32:
        raise ValueError("Invalid Key.")

    if not isinstance(D, tuple):
        raise TypeError("Invalid Data Type.")
    if len(D) != 3:
        raise ValueError("Invalid Data.")

    ciphertext, tag, nonce = D

    cipherObj = _C(_AES(DEK), _GCM(initialization_vector=nonce, tag=tag), _B).decryptor()
    plaintext = cipherObj.update(ciphertext) + cipherObj.finalize()

    return plaintext
