"""
pg-serve/src/serialization.__init__.py/

Goal:
----

**Sign up request flow:**

1. receive input from client via HTTP / JSON -- initialize session (including a token).

2. parse it using parsers

3. authenticate using preset formats (for data types etc.), session mechanism, and context for request.

  3.1. first item in the authenticated information must be the password by design, thus:
    password hashing and returning the hash as the token for the next stage.

4. tokenize info via db and table (part of the request context), assert tokens to each column.

  4.1. tokens asserted to columns that are marked "encrypted" (in the asserted table):
    encrypted via the helpers, each envelope (timestamped) returns as the token.

5. commit change via postgres (with transaction wrap), return positive feedback to client.

6. end session (via expiration of token), discard session token (or store in a separate table, provide both options).

----

**Log-in / Modify request flow:**

1. Receive input via HTTP/JSON and initialize session (token if needed).

2. Authenticate user via password (update last-auth timestamp on stored hash).

3. Parse request parameters:
   - Require authorization via a totp sent to email (if column exists), otherwise do not authorize.
   - Require password rephrase upon updating columns marked "encrypted", or password column (also used to initialize encryption by unwrapping dek).

4. Execute requested action in DB (wrapped in transaction).

5. Return feedback (success/failure) to client and end session.

----

todo:
    -- all of the above...
"""