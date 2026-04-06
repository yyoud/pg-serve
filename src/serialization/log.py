from starlette.requests import Request

from schema.PGSTable import PGSTable


async def process_request(request: Request, table: PGSTable, ):

# tokenless handlers
async def process_signup(request: Request,table: PGSTable):
    # consider request validated.
    # before logging, we need to check the request was strictly checked
    body = request.json()

    password = body[table.password_column]
