"""
pg-serve/src/serialization.__init__.py/

Goal:
----

**Sign up request flow:**

1. receive input from client via HTTP / JSON

2. parse it using parsers

3. authenticate using preset formats (for data types etc.), session mechanism, and context for request.

  3.1. first item in the authenticated information must be the password by design, thus:
    password hashing and returning the hash as the token for the next stage.

4. tokenize info via db and table (part of the request context), assert tokens to each column.

  4.1. tokens asserted to columns that are marked "encrypted" (in the asserted table):
    encrypted via the helpers, each envelope (timestamped) returns as the token.

5. commit change via postgres (with transaction wrap), return positive feedback to client.

6. create payload dict, issue a session token.

----

**Log-in / Modify request flow:**

1. Receive input via HTTP/JSON

2. Authenticate user via password (update last-auth timestamp on stored hash).

3. create payload dict and issue a session token.

4. Parse request's parameters:
   - Require authorization via a totp sent to email/phone (if column exists, if both offer the options to the client or otherwise default to email),
    otherwise do not authorize.
   - Require password rephrase upon updating columns marked "encrypted", or password column (also used to initialize encryption by unwrapping dek).

5. Execute requested action in DB (wrapped in transaction).

6. Return feedback (success/failure) to client and go on to the next request.

7. end session, either via expiration of the token, or by connection loss to the client.

----

todo:
    -- all of the above...
"""