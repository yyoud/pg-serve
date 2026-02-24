#
# Password authentication and password hashing helper functions
# found in docs: `databaseIntegratedUserInterface/userDataHandling/__init__.py/`


from nacl.pwhash.argon2id import (str as _argon2id,
                                  OPSLIMIT_INTERACTIVE as _OPS_INTERACTIVE,
                                  MEMLIMIT_INTERACTIVE as _MEM_INTERACTIVE,
                                  verify as _V)


def hashPassword(P: bytes):
    """
    find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
    :param P: Raw password as bytes.
    :return: hash
    """
    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter.")

    return _argon2id(P, _OPS_INTERACTIVE, _MEM_INTERACTIVE)  # Unchangeable mem and ops limits for convenience. other ones aren't needed really.


def authPassword(P: bytes, H: bytes):
    """
    find docs in databaseIntegratedUserInterface/userDataHandling/__init__.py/
    :param P: Raw password as bytes.
    :param H: Password hash as stored in database (digested from function above.)
    :return: True or False.
    """

    if not isinstance(P, bytes):
        raise TypeError("Invalid Parameter.")

    if not isinstance(H, bytes):
        raise TypeError("Invalid Salt.")

    return _V(H, P)


if __name__ == "__main__":
    print(hashPassword(b'hello im password'))
    print(str(b'hello im password'))
    print(authPassword(b'hello im password', str(b'hello im password')))
