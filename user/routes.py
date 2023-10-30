""" TODO """


import importlib
import importlib.util
import logging
import pprint
from typing import Annotated, Any, Optional, Protocol, Type

from fastapi import APIRouter, FastAPI, Header, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from starlette.responses import PlainTextResponse, RedirectResponse

from oidc_config import AppConstants, OIDCConfig

pp = pprint.PrettyPrinter(indent=4)

from jwt_token.models import GrantTypeEnum, TokenRequestParams
from jwt_token.routes import OIDCToken


class LoggerFactory(Protocol):
    """TODO"""

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """TODO"""
        ...


class SigninRequest(BaseModel):
    username: str
    password: str


class OIDCUser:
    """TODO"""

    _app = None
    _router = None

    def __init__(self, app: FastAPI, oidc_config: dict[Any, Any]):
        pass

    @classmethod
    def _init_module(
        cls,
        app: FastAPI,
        router: APIRouter,
        oidc_config: OIDCConfig,
        logger_factory: Type[LoggerFactory],
    ):
        if not cls._app:
            cls._app = app
            cls._router = router
            cls._oidc_config = oidc_config
            cls._logger = logger_factory.get_logger("OIDCUser")

    @classmethod
    def _process_token_request(cls):
        ...

    @classmethod
    async def configure_routes(
        cls,
        app: FastAPI,
        router: APIRouter,
        oidc_config: OIDCConfig,
        logger_factory: LoggerFactory,
    ):
        """TODO"""

        cls._init_module(app, router, oidc_config, logger_factory)

        # registering the user endpoints
        @cls._router.post(
            "/signin",
            tags=["user_session"],
            summary="user session signin endpoint",
        )
        async def _process_signin_request(
            signin_request: SigninRequest, redirect_uri: Optional[str] = None
        ) -> dict:
            print("\n\n\nprocessing signin request")

            params = TokenRequestParams(
                grant_type=GrantTypeEnum.PASSWORD,
                username=signin_request.username,
                password=signin_request.password,
            )
            jwt_token = await OIDCToken.process_token_for_password(params)

            # print(await request.body())
            # return {"status": "succeeded"}
            redirect_url = f"https://localhost.localdomain/nfme/account?token={jwt_token}"
            print(
                f"\n\n\n{signin_request.username=}, {signin_request.password=}, {redirect_uri=} \n{redirect_url=}"
            )
            response = RedirectResponse(
                url=redirect_url
            )
            response.status_code = 302
            return response

        @cls._router.post(
            "/change_password",
            tags=["user_info"],
            summary="user change password endpoint",
        )
        async def _process_change_password_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/request_password_reset",
            tags=["user_info"],
            summary="user request change password endpoint",
        )
        async def _process_request_password_reset_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/perform_password_reset",
            tags=["user_info"],
            summary="user perform password reset endpoint",
        )
        async def _process_perform_password_reset_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.get(
            "/signout",
            tags=["user_session"],
            summary="user session signout endpoint",
        )
        async def _process_signout_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/activate",
            tags=["user_info"],
            summary="user account activate endpoint",
        )
        async def _process_activate_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/resend_activation_code",
            tags=["user_info"],
            summary="user resend account activation endpoint",
        )
        async def _process_resend_activation_code_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/delete",
            tags=["user_info"],
            summary="user delete account endpoint",
        )
        async def _process_delete_request() -> dict:
            return {"status": "succeeded"}

        @cls._router.post(
            "/signup",
            tags=["user_info"],
            summary="user signup endpoint",
        )
        async def _process_signup_request() -> dict:
            return {"status": "succeeded"}


async def configure_routes(
    app: FastAPI,
    router: APIRouter,
    oidc_config: OIDCConfig,
    logger_factory: Type[LoggerFactory],
):
    """TODO"""

    await OIDCUser.configure_routes(
        app,
        router,
        oidc_config,
        logger_factory,
    )
