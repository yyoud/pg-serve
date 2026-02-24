# a better future -- yyoud, 2025.
# J.Epstein was here


"""
this is databaseIntegratedUserInterface/userDataHandling/__init__.py/

Data first comes from the user into the functions found here. \n
Primitive data types are username and password. those columns cannot be removed in any case.
if are not needed, they may simply be ignored. this is for system integrity. \n

----

Base definitions:
  'secret' information:
    information which will not be permanently stored on the database, as well as stored as briefly as possible inside variables.
    an example of such is a raw password, or unencrypted information (from encrypted columns).
    for changing a password for example, you need to input the original password again, as well as have an active session token (active auth).

  'public' information:
    information which can be permanently stored or tempered with without any form of special or secondary authentication
    from the user, upon the standard one.
    an example of which is a username or a uuid. to change a username, you only need an active session token.

Password:
    * Password policy will be enforced in web before serialization data packaging.
    * will be set as an abstract state of a hash once in and hashed using argon2id.

Other data:
    * Other data can be either encrypted using AES, or left raw.
    * The only information raw by default is username. email, phone number, and payment information(read exp 1)
      must be encrypted using this system.

After the data is processed, it is passed on to the database section, where it will be simply
logged into columns.
Changing of information (password, email, etc.) will have the auth functions set here, yet the changing itself implemented
directly into sqlalchemy with the table class.

----

----

Crypto
----

    This database API implements row-column specific parameter encryption, the specification of how it works are found in the methods below.
    Here, I will cover the threat model the system is designed to protect against, as well as mention and document its known limitations.

    **Threat model:**
        our first step is covering the threat model.
        Since this is a system written in python, the threat model does not include any memory safety guarantees,
        nor guarantee any improved safety over the used libs or modules.



----

**IMPORTANT: INFORMATION LOSS AS A FEATURE**
----

This system incorporates parameter encryption. since, as said clearly above if you read it, I am not rich enough to have an HSM.
Thus, I need to get creative when it comes to how keys work. since the only reliable secret information in this system
is the password given by the user itself, we have to use it as the base secret for the encryption process.
**I do realize it is completely unoptimal and potentially dangerous.**
though it is all we can work with.
given the situation, the best case scenario is to initialize a random dek for each row, then wrap it using a kek,
which will be directly derived from the password (through a process described in mtd 3)
be

----

exceptions:
    1. Payment information cannot be stored yet. only after payment handling will be coded it could be done. for security Reasons.
    2. Any passwordless user must be taken care of using the passwordless handling system provided here. Any other one will not be gurenteed to work.
    3. Hashing algorithm may be discrete and not preset as stated above, need to think this through.
    4. If a non-primitive data type must be changed, there must be an initialized column object for the column.

----
----

methods and definitions:
    1. Encryption method for encrypted columns:
        we need to take into account string, as well as numerical columns, with two different methods.
        each function is *COMPLETELY DEPENDANT* on the primitive column `password`. if the column is not in use,
        no column encryption will be available. \n

        For any row N in table T: \n
          let H be text (string/bytes) column in T; \n
          let Q equal 12 random bytes; \n
          let K be a KEK, derived via mtd 3




    2. define S[N]:
        S[N]; Is the base secret, used for crypto purposes in the internals of the DB. It is the general reliable secret,
        which is why is has no context binding, no timestamping, et cetera.
        digested from password[N]-P[N], and assigned to row[N].
        it is COMPLETELY separated from the password's hash, which will be evaluated using argon2.
        btw do not change the iterations on there because I didn't bother to record it, it's assumed at 65536.

        For every row N in table T: \n
          let P equal password[N]; (raw password or an unkept digest of it that landed through the system) \n
          let B equal 32 random bytes; (salt) \n

          S = (pbkdf2(P || B, iterations=65536), B)


    3. Encryption keys relative to parameters:
        derivation of encryption key, relative to: table, row, nonce.

        For every row N in table T: \n
          let S1 = S[N][0]; \n
          let S2 = S[N][1]; \n
          Key(T, N, Q) = sha3_256(S1 || T.tableKey) \n

        in order to preserve the value of B, we have to add them to the end of the key, to later decompose it and add to the wrapped DEK.

          K= Key(T, N, Q) || $ || S2;


    4. DEK initialization and encryption -- using the derived key:
        using the key, defined in mtd 3, we encrypt a static, 32 byte long random key.

        for every row N:
            let DEK[N] = os.urandom(32); (don't store, apply directly to encryption)\n
            let KEK[N], B = key.split('$') (see mtd 3); \n
            let Q = os.urandom(12); (none) \n
            let wrappedDek[N], tag = AES256GCM(KEK[N], DEK[N]); \n

            encryptedDEK[N] = wrappedDek[N] || $ || tag || $ || Q || $ || B

"""
