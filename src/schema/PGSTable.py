"""
Goals:
    ok so the goal of the system at the end is to recieve input through a json for example,
    serialize the json (through json lib) into a normal python dict,
    and then process the information and insert it into the db. now i already know how to do the first part.

todo:
    -- finish defining PGSTable
    -- et cetera.
"""
from os import urandom
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.schema import Table, MetaData, SchemaItem, Column
from sqlalchemy.inspection import inspect
from sqlalchemy.sql.expression import text
from sqlalchemy.types import String as _SQLString
from sqlalchemy.engine import Engine
from sqlalchemy import column


class PGSTable(Table):
    def __init__(self, name: str, ecrypted_columns: list[str], metadata: MetaData, *args: SchemaItem, **kw: Any):
        """

        :param name: The name of this table as represented in the database.
        :param ecrypted_columns: a list of :class:`Column` names, which marks the columns in the tables of which the
            parameters will be encrypted. Only columns of type :class:`String` (or varchar) can be encrypted, if other
            types of columns are asserted, an error will be raised.
        :param metadata: a _schema.MetaData object which will contain this table.
        """

        columns = [i for i in args if isinstance(i, Column)]

        for i in columns:
            if (not isinstance(i.type, _SQLString)) and (i.name in ecrypted_columns):
                raise TypeError(
                        f"Column '{i.name}' must be String/VARCHAR to be encrypted, "
                        f"not {type(i.type).__name__}"
                    )

        self._table = super().__init__(name, metadata, *args, **kw)

        self.encrypted_columns = ecrypted_columns
        self.tableKey = urandom(32)

        # dict of password column, session token (JWT), timestamp, expiration columns -- from kwargs.
        # {"pw": <col name>, "st": <col name>, "


def ensure_column(engine, table_name, column_name, column_type):
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns(table_name)]

    if column_name not in columns:
        with engine.connect() as conn:
            conn.execute(
                text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            )
            conn.commit()
