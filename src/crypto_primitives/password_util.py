#
# Password authentication and password hashing helper functions
# found in docs: `pg-serve/src/crypto_primitives/crypto_docs_v0.0.txt/`


from nacl.pwhash.argon2id import (str as _argon2id,
                                  OPSLIMIT_INTERACTIVE as _OPS_INTERACTIVE,
                                  MEMLIMIT_INTERACTIVE as _MEM_INTERACTIVE,
                                  verify as _V)


def hash_password(P: bytes):
    """
    find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#2-password-hash-function---argon2id`
    :param P: Raw password as bytes.
    :return: hash
    """
    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter.")

    return _argon2id(P, _OPS_INTERACTIVE, _MEM_INTERACTIVE)  # Unchangeable mem and ops limits for convenience. other ones aren't needed really.


def authPassword(P: bytes, H: bytes):
    """
    find docs in `pg-serve/docs/SECURITY_ARCHITECTURE.md/#2-password-hash-function---argon2id`
    :param P: Raw password as bytes.
    :param H: Password hash as stored in database (digested from function above.)
    :return: True or False.
    """

    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter.")

    if not isinstance(H, bytes):
        raise TypeError("Invalid Salt.")

    return _V(H, P)
