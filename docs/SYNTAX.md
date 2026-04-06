# Here i discuss the planned syntax of using this framework

## Example setting and usage with a simple app

```python

from pgserve import PGServe, PGSTable
# Column, String are directly using sqlalchemy.Column, sqlalchemy.types.String, such that the two are interchangeable.
from sqlalchemy import Column, String # is exactly equal to importing from pgserve.

# define the db interface, engine and driver initialization 
# done by default inside PGSTable

users = PGSTable(r'postgres+psycopg2://mydb/password@localhost/', 
                 Column('username', String, nullable=False), 
                 Column('password', String, nullable=False),
                 Column('secret_personal_info', String), 
                 encrypted_columns=['secret_personal_info'],
                 password_column='password', identifier_column='username')

app = PGServe(r'postgres+psycopg2://mydb:password@localhost/')  # extension of the fastapi FastAPI instance

# now i havent really thought this through after this
# maybe something like

@app.route('/users', validate='strict')  # internal request validation and token processing
def create_user(username, password, very_secret_info):
    users.create(username, password, very_secret_info)
    

```