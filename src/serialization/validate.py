#
# yyoud 2026
# serialization/validate.py
from typing import Literal
from collections.abc import Mapping
from fastapi import Request

from schema.PGSTable import PGSTable, String, Integer, Float, Boolean
from util.exceptions import AuthError, JWTError, ServerError
from util.enum import RequestScopes, PublicEndRequestType


# helpers
async def enforce_attrs(attrs: Mapping[str, type], request: Request, *,
                          scope: RequestScopes = 'body',
                          nullable: list[str] = None,
                          strict: bool = False)-> bool | None:
    """
    Helper function for enforcing attributes to exist in requests.

    :param attrs: asserted default attributes. the mapping shall strictly be ``{<asserted_key>: <asserted_type>}``.
    :param request: starlette request object.
    :param scope: scope of the request (e.g. 'headers', 'query', 'body').
    :param nullable: list of keys indicating if attribute <key> should be treated as nullable.
    :param strict: whether to enforce attribute list and request attributes to exactly match.

    :return: True if passed, False otherwise, for strict checks may raise an AuthError.
    """

    if scope == "headers":
        inf = request.headers

    elif scope == "query":
        inf = request.query_params

    elif scope == "body":
        inf = await request.json()

    else:
        raise ValueError(f"Unknown scope {scope}.")

    if strict:
        if attrs.keys() != inf.keys():
            raise AuthError(f"Expected {len(inf.keys())} attributes, but got {len(attrs)}.") from ValueError()

    if nullable:
        for key in attrs.keys():
            if key not in inf.keys():
                return False

            if key in nullable:
                if inf[key] is not None and not isinstance(inf[key], attrs[key]):
                    return False
            else:
                if not isinstance(inf[key], attrs[key]):
                    return False

    else:
        for key in attrs.keys():
            if key not in inf.keys():
                return False

            if not isinstance(inf[key], attrs[key]):
                return False

    return True


async def validate_tokenized_request(request: Request, table: PGSTable, *, strict: bool = True) -> bool | None:
    # 1. get table schema
    # 2. compare against request body schema
    # 3. that's it basically

    if not request.headers.get("authorization") or request.headers.get("Authorization"):
        raise AuthError("Invalid request: No token for a tokenized request.") from JWTError()


    schema_dict = table.column_schema
    clms = ( clm for clm in tuple(table.columns.values()) if clm.nullable)

    valid = await enforce_attrs(schema_dict, request, strict=strict)

    if not valid:
        return False

    request.state.validated = True
    request.state.strict = strict
    return True


async def validate_tokenless_request(
        request: Request,
        table: PGSTable,
        request_type: PublicEndRequestType,
        *,
        strict: bool = True,
        password_column: str = None,
        identifier_column: str = None
        ) -> bool | None:
    """
    :param request: starlette request object.
    :param table: table to validate.
    :param request_type: endpoint type to validate.
    :param strict: whether to enforce attribute list and request attributes to exactly match.
    :param password_column: password column in default table.
    :param identifier_column: identifier column in default table.
    """


    if request_type == "signup":
        return await validate_tokenized_request(request, table, strict=strict)

    elif request_type == "login":
        # check password and id are in the request
        # then uh that's it
        # now remember its only the request validation,
        # not the authentication.
        # you need to implement that in the middleware, or else in another
        # file that the middleware would use. remember that.
        password_column = password_column or table.password_column
        identifier_column = identifier_column or table.identifier_column

        return await enforce_attrs({identifier_column: str, password_column: str}, request, strict=strict)

    else:
        raise AuthError(f"Unknown request type {request_type}.") from ValueError()


async def validate_fields(request: Request, fields: Mapping[str, type],
                          table: PGSTable, *,
                          strict: bool = True) -> bool | None:

    # check if the field exists in the table
    schema = table.column_schema.keys()

    for key in fields.keys():
        if not key in schema:
            raise ServerError(f"Field {key} not in schema.") from ValueError()

    return await enforce_attrs(fields, request, strict=strict)
