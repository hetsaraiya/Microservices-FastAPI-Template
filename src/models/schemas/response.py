from dataclasses import Field
from typing import Generic, TypeVar, Optional
from pydantic.generics import GenericModel

from src.models.schemas.base import BaseSchemaModel

T = TypeVar("T", bound=BaseSchemaModel)

class Response(GenericModel, Generic[T]):
    status: bool
    message: str
    data: Optional[T] = None
    error: Optional[str] = None