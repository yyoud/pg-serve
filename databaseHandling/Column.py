from typing import final, Literal


@final
class Column:
    def __init__(self, name: str,
                 type: Literal['int', 'float', 'bytes', 'string', 'boolean', 'list'],
                 acceptsNullType: bool = True,
                 isMainID: bool = False,
                 isEncrypted: bool = False,
                 staticMACHash: bytes = None):
        self.name = name

        if not isinstance(type, (str, ('int', 'float', 'bytes', 'string', 'boolean', 'list'))):
            raise ValueError("Unsupported Column Type")

        self.type = type


        self.acceptsNullType = acceptsNullType

        if isinstance(self.type, (str, ('int', 'float', 'string'))) and isMainID:
            self.isMainID = isMainID
        elif isMainID:
            raise ValueError("Only Columns of types: int, float, string can be set to be main ID.")

        if isEncrypted and isinstance()

