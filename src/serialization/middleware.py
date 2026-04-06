from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from session.validate import validate_token
from validate import validate_tokenized_request, validate_tokenless_request
from app import PGServe
from util.exceptions import AuthError, JWTError, SignatureError, SigningKeyError


class _ValidationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: PGServe, signing_key: bytes):  # should i pu the signing key here;
        super().__init__(app)
        self.app = app
        self.signing_key = signing_key

    async def dispatch(self, request: Request, call_next):
        try:
            validated = await self.app.validate_request(request, signing_key)  # or self.signing_key
            if not validated:
                raise JWTError("Invalid JWT.")

        except AuthError:
            raise HTTPException(status_code=401, detail="Authentication error, please try again.")

        except(JWTError, SignatureError, SigningKeyError):
            raise HTTPException(status_code=401, detail="Authorization error, please try again. ")

        except Exception:
            raise HTTPException(status_code=400)  # be cold mog them innit

        return await call_next(request)


# we have a similar issue with this class as well, this time with the table.
# i think ive told you sometime that i mitigated a table name switch vulnerability
# where the client trys to switch the table name in the incoming request.
# thus, the final mitigation is (very opinionated) to route all tokenless requests to one table or to an identifier-based
# table routing function.
# now the problem is that we need to verify the schema here, which btw is also a problem for some fields.
# wow i uh just realized i need to issue a problem in my note for my design, and a very serious one too.
# let me do that fix.
# the problem is that if the method is UPDATE or PATCH or whatever its called, i only need to
# verify the chosen field. if strict, i might just check the password as well
# (and also obviously demand its being in the request body.
class _TokenProcessingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: PGServe):
        super().__init__(app)
        self.app = app

    async def dispatch(self, request: Request, call_next):
        try:
            # so here the thing is we have to get a table somehow so im js gonna
            # be lazy and assert the default table

            # load the mrtadata schema, see which columns are encrypted and start calculating bro
            # gotta split the responsibilities

            pass

        except Exception:
            pass