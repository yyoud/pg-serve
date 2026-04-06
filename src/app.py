# to be developed.
#filler for cli uvicorn app

from typing import Literal

import fastapi
from sqlalchemy.util import await_only

from schema.PGSTable import PGSTable, Engine

from serialization.validate import validate_tokenized_request, validate_tokenless_request
from session.validate import validate_token
from util.enum import PublicEndRequestType

app = fastapi.FastAPI(title="pg-serve", version="1.0.0")

class PGServe(fastapi.FastAPI):
    def __init__(self,
                 engine: Engine,
                 default_table: str,
                 transport_kek: bytes,
                 *args: PGSTable,
                 public_end_request_type_field: tuple[str, str] = None,
                 JWT_field: str = None,
                 **kwargs):
        """
        :param engine: global engine object.
        :param default_table: default table routing. asserted via name.
        :param signing_key: JWT signing key.
        :param transport_kek: JWE transport key.
        :param args: available tables for the app.
        :param public_end_request_type_field: tuple containing custom names for the public-end request type.
            Typed as (<login_field>, <signup_field>), defaults to 'login' and 'signup'.
        :param JWT_field: JWT field name. defaults to 'authorization'.

        """

        super().__init__(**kwargs)
        self.engine = engine
        self.transport_kek = transport_kek  # runtime is trusted.

        self._MAP = {table.name: table for table in args}

        if not self._MAP.get(default_table):
            raise ValueError("Invalid default table.")

        self.default_table = default_table

        self.request_type_field = public_end_request_type_field or PublicEndRequestType
        self.JWT_field = JWT_field or 'authorization'


    @property
    def MAP(self):
        return self._MAP

    def add_table(self, table: PGSTable):
        self._MAP[table.name] = table

    def remove_table(self, __del__: str | list[str]):
        if isinstance(__del__, str):
            return self._MAP.pop(__del__)

        deleted = []
        for name in __del__:
            deleted.append(self._MAP.pop(name))
        return tuple(deleted)  # immutable




    async def validate_request(self, request: fastapi.Request,
                               signing_key: bytes, *,
                               table: str = None,
                               strict: bool = True
                               ):
        """
        :param request: a starlette request object.
        :param signing_key: JWT signing key.
        :param table: table name as assigned at initialization.
        :param strict: whether to enforce attribute list and request attributes to exactly match.
        """
        is_tokened = self.JWT_field in request.headers

        if table and not self._MAP.get(table):
            raise ValueError("Invalid table.")

        table = self._MAP.get(table) or self._MAP.get(self.default_table)


        if is_tokened:
            token = request.headers.get(self.JWT_field)
            if not token:
                raise fastapi.HTTPException(status_code=401, detail="Invalid token.")

            isTokenValid = validate_token(token.encode(), signing_key)

            if not isTokenValid:
                raise fastapi.HTTPException(status_code=401, detail="Invalid token.")

            return await validate_tokenized_request(request, table)

        request_type: PublicEndRequestType
        if request.headers.get(self.request_type_field[0]):
            request_type = PublicEndRequestType.LOGIN

        elif request.headers.get(self.request_type_field[1]):
            request_type = PublicEndRequestType.SIGNUP

        else:
            raise fastapi.HTTPException(status_code=400, detail="Invalid request type.")

        return await validate_tokenless_request(
            request, table,
            request_type,
            strict=strict,
            password_column=table.password_column,
            identifier_column=table.identifier_column
        )




def run(p, p2, p3):
    pass
