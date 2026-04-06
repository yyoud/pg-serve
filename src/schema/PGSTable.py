"""
todo:
    -- build the crud interface and start integrating with the app interface
    -- build the mechanism that creates the internal tables for pgserve's metadata
       (table of table key and encrypted column names)
    -- at least try to optimize for micro benching

more precise
1. init:
 -- make sure primary key column, id column, password columns arent in the encrypted column list
 -- do it upon reload from metadata as well.
 -- find a solution to the super.init problem. idk how youll reload everyhthing its a mess.
    maybe just stop working with sqlalchemy's orm completely, or just idk limit the dependency.
    it aint like its that important in this project.
    either way it cant stay the way it is.
"""

from __future__ import annotations

from json import dumps, loads
from os import urandom
from typing import Any

# i know noqa is bad but lemme finish the base development
# before judging

from sqlalchemy import create_engine, Connection  # noqa
from sqlalchemy.schema import Table, MetaData, SchemaItem, Column
from sqlalchemy.inspection import inspect  # noqa
from sqlalchemy.sql.expression import text  # noqa
from sqlalchemy.types import String, Integer, Float, Boolean
from sqlalchemy.engine import Engine # noqa
from sqlalchemy import column  # noqa
from base64 import b64encode as _b64e, b64decode as _b64d


# noinspection SqlNoDataSourceInspection
class PGSTable(Table):
    def __init__(self,
                 engine: Engine,  # global engine
                 name: str,
                 metadata: MetaData,
                 *args: SchemaItem,
                 encrypted_columns: list[str] | None = None,
                 password_column: str | None = None,
                 identifier_column: str | None = None,
                 **kw: Any):
        """
        The instance of the postgres tables that PG serve is designed to interact with.


        For a re-initialized instance (an existing table), leave the below keyword arguments blank.
        Either way, they will be ignored in such case and reloaded from the database.

        :param name: The name of this table as represented in the database.

        :param metadata: a _schema.MetaData object which will contain this table.

        :param encrypted_columns: a list of column names, which marks the columns that will be encrypted.
           Those that are must be of type String (varchar).

        :param password_column: the name of the password column for this table.
            If None and the table is initialized for the first time, No encryption could be done.

        :param identifier_column: the name of the default identifier column for this table.
            If None and the table is initialized for the first time, No default column will be set.
        """



        columns = [i for i in args if isinstance(i, Column)]

        if encrypted_columns:
            for i in columns:
                if (not isinstance(i.type, String)) and (i.name in encrypted_columns):
                    raise TypeError(
                            f"Column '{i.name}' must be String/VARCHAR to be encrypted, not {type(i.type).__name__}"
                    )

        # how am I supposed to load a table from the db into this kind of obj?
        # you're not bro only the kwargs are needed to be loaded
        # wait, I do need to. I do not have the table's columns upon reinit. so uh I need to figure it out
        t = super().__init__(name, metadata, *args, **kw)

        metadata.create_all(engine)

        self.engine = engine
        self.name = name

        conn = self.engine.connect()

        # check if table exists to load metadata
        mainExists: bool = conn.execute(
            text("""
                 SELECT EXISTS (SELECT 1 
                                FROM pg_tables 
                                WHERE schemaname = :schema AND tablename = :name);
                     
                """),
            {'name': name, 'schema': (t.schema or 'public')}
        ).scalar()

        metaExists: bool = conn.execute(
            text("""
            SELECT EXISTS (SELECT 1
                           FROM pg_tables
                           WHERE schemaname = :schema AND tablename = :name);
            """),
            {'schema': (t.schema or 'public'), 'name': f'_{name}_pgserve_metadata'}
        ).scalar()

        # first init
        if not mainExists and not metaExists:
            self.encrypted_columns = encrypted_columns
            self.tableKey = urandom(32)
            self.password_column = password_column
            self.identifier_column = identifier_column

            # create metadata table
            self._create_metadata(self.encrypted_columns, _b64e(self.tableKey).decode(), conn)
            conn.close()
            return

        # xor, true when only one of them is true and the other isn't.
        elif mainExists ^ metaExists:
            raise RuntimeError("Corrupt table.")

        # load metadata table
        pgserve_metadata = self._load_metadata(conn)

        conn.close()

        # assert params
        # noinspection PyTypeChecker
        self.encrypted_columns = loads(pgserve_metadata[0])
        self.tableKey = _b64d(pgserve_metadata[1].encode())


    @property
    def column_schema(self) -> dict[str, type]:
        TYPE_MAP = {
            String: str,
            Integer: int,
            Float: float,
            Boolean: bool,
        }

        #noinspection PyTypeChecker
        return {col.name: TYPE_MAP[type(col.type)] for col in self.columns}

    def _load_metadata(self, conn: Connection):
        d = conn.execute(
            text(
                f"""
                SELECT * FROM _{self.name}_pgserve_metadata;
                """
            )).fetchall()

        return d

    def _create_metadata(self, encrypted_columns: list[str], table_key: str, conn: Connection) -> None:
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS _{self.name}_pgserve_metadata (  -- IDK if it'll work
                    encrypted_columns TEXT,
                    table_key  VARCHAR(44),  -- base64 encoded 32 byte key
                    password_column VARCHAR,
                    ID_column VARCHAR
                );
                
                INSERT INTO _{self.name}_pgserve_metadata VALUES (:encrypted_columns, :table_key)

                """
            ),
            {'encrypted_columns': dumps({'columns': encrypted_columns}), 'table_key': table_key}
        )

        conn.commit()


    def fetch(self, identifier: str | int, columns: str | tuple[str], *, custom_id: str = None):
        clmn = columns if isinstance(columns, str) else ', '.join(columns)


        sql = text(
            f"""
            SELECT {clmn} FROM {self.name} WHERE {(custom_id or self.identifier_column)} = :identifier; 
            """
        )
        with self.engine.connect() as conn:
            echo = conn.execute(sql,
                         {'identifier': identifier}).fetchall()

        return echo

    def put(self, data: dict[str, Any]):
        pass
    #CRUD- create, read, update, delete
