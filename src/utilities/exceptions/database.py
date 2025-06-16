from fastapi import HTTPException, status

class EntityDoesNotExist(Exception):
    """
    Throw an exception when the data does not exist in the database.
    """
    def __init__(self, detail: str):
        super().__init__(detail)


class EntityAlreadyExists(Exception):
    """
    Throw an exception when the data already exist in the database.
    """
    def __init__(self, detail: str):
        super().__init__(detail)