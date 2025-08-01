import datetime
import typing

import pydantic

from src.utilities.formatters.datetime_formatter import format_datetime_into_isoformat
from src.utilities.formatters.field_formatter import format_dict_key_to_camel_case


class BaseSchemaModel(pydantic.BaseModel):
    class Config(pydantic.BaseConfig):
        orm_mode: bool = True
        validate_assignment: bool = True
        allow_population_by_field_name: bool = True
        alias_generator: typing.Any = format_dict_key_to_camel_case
        populate_by_name = True
        aliases = {
            "client_data": "clientData"
        }
