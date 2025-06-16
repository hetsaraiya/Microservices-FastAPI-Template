import typing
import uuid

import sqlalchemy
from sqlalchemy.orm import DeclarativeBase
from uuid import UUID


class DBTable(DeclarativeBase):
    metadata: sqlalchemy.MetaData = sqlalchemy.MetaData()  # type: ignore


Base: typing.Type[DeclarativeBase] = DBTable

# Helper function to generate UUID
def generate_uuid() -> str:
    return str(uuid.uuid4())
