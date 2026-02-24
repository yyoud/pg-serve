"""
Goals:
    ok so the goal of the system at the end is to recieve input through a json for example,
    serialize the json (through json lib) into a normal python dict,
    and then process the information and insert it into the db. now i already know how to do the first part.
    the thing is that i need
"""
from os import urandom
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.schema import Table, MetaData, SchemaItem, Column
from sqlalchemy.inspection import inspect
from sqlalchemy.sql.expression import text
from sqlalchemy.types import Integer, String
from sqlalchemy.engine import Engine


class TableExtension(Table):
    def __init__(self, name: str, metadata: MetaData, *args: SchemaItem, **kw: Any):
        super().__init__(name, metadata, *args, **kw)
        self.tableKey = urandom(32)


# helper functions

def ensure_column(engine, table_name, column_name, column_type):
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns(table_name)]

    if column_name not in columns:
        with engine.connect() as conn:
            conn.execute(
                text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            )
            conn.commit()


if __name__ == "__main__":
    # E = create_engine("postgresql+psycopg2://user:password@localhost:5432/mydb")
    # M = MetaData()
    # T = Table("expiramentTable", M,
    #           Column("password", String))
    pass