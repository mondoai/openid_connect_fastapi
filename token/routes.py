""" TODO """

from typing import Annotated

from fastapi import Header


def init_module(app, conf):
    """TODO"""

    @app.get("/authorize", tags=["authorization"])
    async def root(
        qauthorization: Annotated[str | None, Header()],
        user_agent:    Annotated[str | None, Header()] = None,
    ) -> dict:
        print(user_agent)
        print(qauthorization)
        return {"Ping": "Pong"}



"""TODO"""
import pprint
from typing import Any

from fastapi import APIRouter, FastAPI
from fastapi.responses import PlainTextResponse
from jwcrypto import jwk

pp = pprint.PrettyPrinter(indent=4)


class AppConstants:
    """TODO"""

    AUTHORIZATION_ENDPOINT = "/authorize"
    TOKEN_ENDPOINT = "/token"
    USERINFO_ENDPOINT = "/userinfo"
    JWKS_ENDPOINT = "/jwks"
    JWKS_X5C_ENDPOINT = "/jwks/x5c"


class OIDCAuthorization:
    """TODO"""
    _app = None
    _router = None

    def __init__(self, app: FastAPI, oidc_config: dict[Any, Any]»):
        pass

    @classmethod
     def _init_module(cls, app: FastAPI, router: APIRouter, oidc_config: dict[Any, Any]):
        if not cls._app:
            cls._app = app
            cls._router = router

    @classmethod
    def configure_routes(cls, app: FastAPI, router: APIRouter, conf: dict[Any, Any]):
        """TODO"""

        cls._init_module(app, router, conf)

        # registering the jwks endpoints
        @cls._router.get(
            "/jwks",
            tags=[" jwks "],
            summary="Get the server's JWKS",
        )
        async def get_jwks() -> dict:
            return {"keys": [cls.public_jwk]}

        # registering the jwks x5c endpoint
        @cls._router.get(
            "/jwks/x5c",
            tags=[" jwks "],
            summary="Get the server's X5C cerrificate",
            response_class=PlainTextResponse,
        )
        async def get_jwks_x5c() -> str:
            return cls._public_key

        @cls._router.get(
            "/.well-known/openid-configuration",
            tags=[" jwks "],
            summary="OpenID-Connect discovery endpoint",
        )
        async def get_well_known_spec() -> dict:
            return cls._oidc_configuration


def configure_routes(app: FastAPI, router: APIRouter, conf: dict[Any, Any]):
    """TODO"""

    OIDCAuthorization.configure_routes(
        app,
        router,
        conf["openid_connect_fastapi"],
    )
