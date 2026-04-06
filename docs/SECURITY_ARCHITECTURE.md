# Security architecture and Threat-Model

---

## Password management
passwords are managed once received and serialized.
This process is trusted via [runtime trust](#assumption-runtime-trusted).

### On sign-up:
The password is tokenized from the parsed input, 
then used to encrypt the other tokenized parameters asserted to columns that are marked in the 
"encrypted columns" list of the asserted table
(see [serialization](../src/serialization/__init__.py), [PGSTable](../src/schema/PGSTable.py)).

After encryption process (and DEK wrapping), the password token is hashed using Argon2id (see [method 2](#2-password-hash-function---argon2id)).
The old raw password token is then immediately removed, to be replaced by the hash.
After a successful sign-up process, 
will by default 

### On log-in:
The password is tokenized from the parsed input, to be immediately hashed and compared 
to the previously asserted password hash.
If successful, a payload dict is created and a [session token](#session-token) issued.

The request specifications will be serialized and commited (if additional requirements will succeed) later on,
only when the authentication token is asserted true.

---

## Session management
A session is an attribute created upon connection with the client after authentication, 
and eradicated upon expiration or end of the connection.
The session is identified via a JWT session token, which expires after a set amount of time.

### Session token:
A JWT session token is the authentication signature. it is assembled from the following parts, all encoded in [base 64](https://docs.python.org/3/library/base64.html#base64.b64encode):
1. Payload -- A JSON file containing "sub" (subject, user id), "iat" (issued at, timestamp of issue in secs), "exp" (timestamp of expiration in secs).
2. Signature -- An HMAC digest of the payload and header separated by a `.`, with a secret key.
3. Header -- A JSON file containing "alg" (algorithm used for signature), "typ" (type of token, defaults to "JWT").

The key will be formatted as: `<header>`**.**`<payload>`**.**`<signature>`.

### Secret key:
A random, 256-bit key, used to sign the payload in the session token. The key can be loaded from an environment variable, 
and a .PEM file.

It shall be rotated frequently, though it is not enforced because of the environment limitations.

...

---

---

## Cryptography functions and methods


### 1. KEK & DEK generation
#### A KEK will be generated as thus:
1. Stretching -- Put the raw password into a PBKDF2 process, along with a random pre-generated salt of 128 bits.
   (see function [S(P, B)](https://github.com/yyoud/pg-serve/blob/main/src/crypto_primitives/dek_util.py/#L17-L32)).
   The function uses the `SHA3-256` algorithm, as well as 262144 (2^18) iterations.
   The function returns a tuple `(S1, S2)` (where `S1` is the secret itself - not permanently stored; `S2` is the salt, kept and stored
   in the wrapped DEK).

2. Expansion -- The output will on-go into an HKDF, where it will be mandatorily context-bound to the table key, 
   and optionally bound to additional context
   (value of [PRIMARY KEY](https://docs.sqlalchemy.org/en/20/glossary.html#term-primary-key) column). 
   The HKDF also uses `S2` as a salt, in order to decrease the amount of random variables needed to be kept.
   The HKDF returns as a tuple `(KEK, S2, context)` (where `context` is the concatenation of `table key`+`optinal context`)

This process is an implementation of the [NIST SP 800-132](https://csrc.nist.gov/News/2023/proposal-to-revise-nist-sp-800-132-pbkdf)
recommendation for Password-Based Key Derivation. (see [SP 800-132, december 2010, section 5.4, option 2b](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)).

The tuple returned by the HKDF needs to be passed as is to the dek wrapping function.

##

#### A dek 
is generated using [`os.urandom(32)`](https://docs.python.org/3/library/os.html#os.urandom).
The specific length of 32 bytes (256 bits) is needed for the AES-256 algorithm to work properly.

---

### 1.1. DEK wrapping using the KEK
The DEK is encrypted by [AES-256](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES256) 
[GCM](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM) algorithm.
It uses the KEK as the key, and a [random 96-bit nonce](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher:~:text=NIST%20recommends%20a%2096%2Dbit%20IV%20length) 
generated via os.urandom(12).

It is preserving the random variables it got from past stages, to reconstruct the KEK at decryption.
Thus, it is formatted as a length based partition, as the wrapped key is stored encoded into base 64 in the database.

---

### 2. Password hash function - Argon2id
The used password hash fucntion in this API is [PyNaCl Argon2id](https://pynacl.readthedocs.io/en/latest/api/pwhash/#nacl.pwhash.str).
The constants (`MEMLIMIT`, `OPSLIMIT`) are by default set to [`MEMLIMIT INTERACTIVE`](https://pynacl.readthedocs.io/en/latest/api/pwhash/#nacl.pwhash.MEMLIMIT_INTERACTIVE)
and [`OPSLIMIT INTERACTIVE`](https://pynacl.readthedocs.io/en/latest/api/pwhash/#nacl.pwhash.OPSLIMIT_INTERACTIVE).

---

### 3. Data encryption
This library can encrypt certain data before it is stored in database.
It does so with AES-256 GCM, using the DEK as the encryption key, along with a random nonce generated via os.urandom(12).

Since the DEK is wrapped by a password-derived KEK, a password loss will unfortunately mean loss of all encrypted data
on the database (see [known limitation 3](#known-limitation-data-loss)).

---

---

## Threat model
The general model on which the security architecture is guided and built upon.

### Assumptions


1. Runtime is trusted -- We assume no memory leaks/dumps from RAM, no access to internal memory at all by an attacker.  <a id="assumption-runtime-trusted"></a>
2. Database is not trusted -- Database environment is considered exploited/visible to an attacker at all times.
3. Primitives are trusted -- All the used Cryptography primitives are implemented correctly and audited.
4. Client itself not trusted -- Client assumed to be a potential attacker.
5. Client side is not exploited -- The client's computer does not contain any malicious software that may grant full/part access to the computer for an attacker.
6. Encrypted protocols are trusted -- HTTPS & TLS are assumed to be secure connections with proper encryption and authentication (MAC).
7. Client connection is secure -- Assume HTTPS/TLS are used, thus making the connection encrypted and secure.
8. Server Physically protected -- Server is not accessible to unauthorized personnel.
9. Client is not under physical attack -- Assume no attacker beats the client with a wrench for the password .


### Protected threats
1. side channel attack:
    protects against side channel/timing attacks by using [PyNaCl](https://pynacl.readthedocs.io/en/) [`verify`](https://pynacl.readthedocs.io/en/latest/api/pwhash/#nacl.pwhash.verify)

2. Database exploit:
   Database exploits are mitigated via encryption of kept/protected information.


### Known limitations
1. No protection against memory dumps/runtime exploits. This is unfortunately impossible to do reliably with python.
2. No protection against server-side DNS spoofing.
3. No data recoverability -- If the user loses the password, all the encrypted data is lost. This is the case because unfortunately 
   I do not have the right equipment (HSM) for handling/implementing the appropriate key hierarchy needed for that. <a id="known-limitation-data-loss"></a>
4. Physical/Mental attacks ($5 wrench attack) are out of scope.
