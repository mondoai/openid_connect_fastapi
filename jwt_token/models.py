"""TODO"""
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Optional

from fastapi import FastAPI, Header
from fastapi.param_functions import Query
from pydantic import BaseModel, Field, HttpUrl
from pydantic.networks import UrlConstraints
from pydantic_core import Url


class GrantTypeEnum(Enum):
    AUTHORIZATION_CODE = "authorization_code"
    PASSWORD = "password"
    REFRESH_TOKEN = "refresh_token"


class TokenRequestParams(BaseModel):
    grant_type: GrantTypeEnum = Field(
        ...,
        description="Only 'authorization_code' , 'password', and 'refresh_token' are supported",
    )
    code: str = Field(
        None,
        description="The authorization code issued via the Authorization Request endpoint - required for authorization_code grant_type",
    )
    redirect_uri: Annotated[
        Url,
        UrlConstraints(max_length=2083, allowed_schemes=["https"]),
        Field(
            None,
            description="The same redirect_uri registered for the client, and must be identical to the redirect_uri parameter value that was included in the initial Authorization Request  - required for authorization_code grant_type",
        ),
    ]
    client_id: str = Field(
        None,
        description="The client_id - required for authorization_code grant_type",
    )
    username: str = Field(
        None,
        description="The resource owner's username - rquired for the password grant_type",
    )
    password: str = Field(
        None,
        description="The resource owner's password - rquired for the password grant_type",
    )
    scope: str = Field(
        None,
        description="The scope - optional for the both password and refresh_token grant_types",
    )
    refresh_token: str = Field(
        None,
        description="The refresh_token - rquired for the refresh_token grant_type",
    )
