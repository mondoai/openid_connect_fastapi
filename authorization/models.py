"""TODO"""
from dataclasses import dataclass
from typing import Optional

from fastapi.param_functions import Query
from pydantic import BaseModel, Field, HttpUrl


class ClientAuthorizationRegistry(BaseModel):
    """TODO"""
    redirect_uri_hostname: str
    redirect_uri_port: str
    redirect_uri_path: str
    description: str
    client_id: str
    username: str
    password: str


@dataclass
# class AuthorizationGetParams(BaseModel):
class AuthorizationGetRequest:
    """TODO"""

    client_id: str = Query(
        ..., description="client id which is registered with this OP"
    )
    redirect_uri: str = Query(
        ..., description="redirect uri back to the client", regex="^https://.*"
    )
    scope: Optional[str] = Query(
        None, description="Requested Authentication Context Class Reference values"
    )
    response_type: Optional[str] = Query(
        None, description="only authorization code flow is supported"
    )
    state: Optional[str] = Query(
        None,
        description="Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) ",
    )
    response_mode: Optional[str] = Query(
        None,
        description="Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.",
    )
    nonce: Optional[str] = Query(
        None,
        description="String value used to associate a Client session with an ID Token, and to mitigate replay attacks",
    )
    display: Optional[str] = Query(
        None,
        description="ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.",
    )
    prompt: Optional[str] = Query(
        None,
        description="Only login prompt type is supported by the current implementation, that specifies the Authorization Server is to prompt the End-User for reauthentication and consent",
    )
    max_age: Optional[str] = Query(
        None,
        description="Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.",
    )
    ui_locales: Optional[str] = Query(
        None,
        description="End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values",
    )
    id_token_hint: Optional[str] = Query(
        None,
        description="ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client",
    )
    login_hint: Optional[str] = Query(
        None,
        description="Hint to the Authorization Server about the login identifier the End-User might use to log in",
    )
    acr_values: Optional[str] = Query(
        None, description="Requested Authentication Context Class Reference values"
    )


class AuthorizationRequest(BaseModel):
    """TODO"""

    client_id: str = Field(
        ..., description="client id which is registered with this OP"
    )
    redirect_uri: HttpUrl = Field(..., description="redirect uri back to the client")
    scope: Optional[str] = Field(
        None, description="Requested Authentication Context Class Reference values"
    )
    response_type: Optional[str] = Field(
        None, description="only authorization code flow is supported"
    )
    state: Optional[str] = Field(
        None,
        description="Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) ",
    )
    response_mode: Optional[str] = Field(
        None,
        description="Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.",
    )
    nonce: Optional[str] = Field(
        None,
        description="String value used to associate a Client session with an ID Token, and to mitigate replay attacks",
    )
    display: Optional[str] = Field(
        None,
        description="ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.",
    )
    prompt: Optional[str] = Field(
        None,
        description="Only login prompt type is supported by the current implementation, that specifies the Authorization Server is to prompt the End-User for reauthentication and consent",
    )
    max_age: Optional[str] = Field(
        None,
        description="Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.",
    )
    ui_locales: Optional[str] = Field(
        None,
        description="End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values",
    )
    id_token_hint: Optional[str] = Field(
        None,
        description="ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client",
    )
    login_hint: Optional[str] = Field(
        None,
        description="Hint to the Authorization Server about the login identifier the End-User might use to log in",
    )
    acr_values: Optional[str] = Field(
        None, description="Requested Authentication Context Class Reference values"
    )
