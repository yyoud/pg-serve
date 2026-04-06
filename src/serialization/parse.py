from fastapi import Request, FastAPI
import xmltodict


async def parse_xml_body(request: Request) -> dict:
    """
    Parses the XML body of a request.
    Not recommended using. if possible, switch to JSON formatted requests.

    :param request: starlette request object.

    :return: parsed XML as python dict.
    """
    body = await request.body()
    data = xmltodict.parse(body.decode())
    if isinstance(data, dict) and len(data) == 1:
        data = list(data.values())[0]
    return data
