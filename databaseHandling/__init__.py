# there's no future we're all going to hell -- evil yyoud, 2025.

"""
this is databaseIntegratedUserInterface/databaseHandling/__init__.py/

terms:
    * 'exp[n]' refers to the exception with respect to number n found under the 'exceptions' category.
    * 'mtd[n]' refers to a method of implementation, found under the 'methods and definitions' category with respect to number n.
    * 'row[n]' strictly refers to the nth index found in any general instance of table.
    * 'userDataHandling' refers to directory `databaseIntegratedUserInterface/userDataHandling/__init__.py/`, in this project.


This system will implement a database and user authentication and cryptographically secure data processing and handling.
At its base, it will use **SQLAlchemy** as its engine and lower level table placement.
every table instance will have its own engine, and the columns will be simply "parsed" (more accurately; placed into) into sqlalchemy
columns using the instance of the table.
PLEASE DO NOT DEFINE ANY PERMANENT USER CLASS.


all data will be accessible to the database only after authentication, done by functions implemented at userDataHandling.

Primitive columns are:
 * password("password", 'bytes', False)
 * username("username", 'string', False, isMainID=True)
they can't be removed.

Process:
    On each data input into the table, a new row gets created.
    Unset values will default to null on columns that accept nullType.

----


Definitions
----

Base definitions:
  'secret' information:
    information which will not be permanently stored on the database, as well as stored as briefly as possible inside variables.
    an example of such is a raw password, or unencrypted information (from encrypted columns).
    for changing a password for example, you need to input the original password again, as well as have an active session token (active auth).

  'public' information:
    information which can be permanently stored or tempered with without any form of special or secondary authentication
    from the user, upon the standard one.
    an example of which is a username or a uuid. to change a username, you only need an active session token.

----

Column:
    any non-primitive column is a `Column` object initialized with the below parameters:
      * String name;
      * String type [one of the primitives str, int, float, bytes, boolean, list, and maybe dict];
      * Boolean acceptsNullTypes;
      * Boolean isMainID [only for columns with types str, int, float. sets to username by default. no table with more than one mainID column.]; (see exp 1)
      * Boolean isEncrypted [only for types str, bytes];

    generated initialized fields:
      * bytes columnHash

Table:
    a table is a list of column objects. any table by default includes the preset primitive columns, stated above.
    a table will be set as an object `Table`, which of parameters are stated below:
      * list[Column...] initialColumnComposition;
      * String name;
      * String mainIdColumn; (see exp 2)

    generated initialized fields:
      * bytes tableKey; (see mtd 2)


----

exceptions:
    1. when a table receives more than one column that is defined as 'isMainID' and no 'mainIdColumn', it will ignore both commands and assert the 'username' column as main id.
    2. when a table receives a valid 'mainIdColumn' as a parameter, the parameter overrides the preset main ID columns.
    3. method(s) of encryption for encrypted columns are found rigorously in `userDataHandling/__init__.py/`
    4. if on any input to a table, there are left unfilled columns that do not accept nullType, the row will be discarded, and an error report will shoot back.
    5. i know the encryption method (that uses passwords) is not optimal. i dont know aws yet and dont want to waste money on an hsm yet. when ill graduate highschool i might purchase a high level hobby or an enterprise hsm, and work on it.

----

methods and definitions:
    1. table key:
        a static key that is automatically assigned for every table upon creation.
        it is generated randomly using `os.urandom(32)` from lib 'os'.
        it is universally 256 bits.

    2. column hash variable--deprecated; unused and useless for anything, except maybe export the db. it will be kept in docs but not yet implemented until resolved.
        for any encrypted numeric/text column:
        the hash is seeded using the column's static id (see mtd 4).

        For any numeric column K:
          the hash will be calculated in the following way.
          take K(n) as a numerical value for every row[n] in array K (n>=0).
          C, F, ω are state variables indexed by iteration n.
          H[0] is the initialization vector, defined by sha256(columnStaticID) (see mtd 4)

          for each value:
            C[0] = 0
            F[-1] = 1
            ω[-1] = 0

          set values, relative to current n:
            let float C[n]=sum(x=0, upbound=n, K(x)); cumulative value.
            let float F[n]=product(x=0, n, C[n]/C[n-1]); relative accumulation value
            let float ω[n]=mod(K(n)^C[n], F[n]);

          for each n:
            H[n+1] = sha256(H[n] || bytes(ω[n]))
          H[f] will be set as the column hash.

        For any text column K:
          take K(n) as a textual value for every row[n] in array K.
          H[0] is the initialization vector, defined by sha256(<defined via mtd 4>)

          for each n:
            H[n+1] = sha256(H[n] || K(n))
          H(f) will be set as the column hash.

    3. column static id:
        a uuid4, assigned to every column no matter its type, using the standard uuid4 function from lib 'uuid'.
        comes to serve as a seed for any potential references, via mtd 5.

    4. local access paths:
        a string of referred ids of columns, defined by '/<root>/<subpart>'.
        root is defined as the asserted unique table id (see mtd 4.1)
        subpart is defined as the asserted unique column id.


"""
