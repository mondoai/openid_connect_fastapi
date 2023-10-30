""" TODO """


import importlib
import importlib.util
import logging
import pprint
from dataclasses import asdict
from typing import Any, Protocol, Type
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse

# from fastapi.responses import PlainTextResponse

from oidc_config import AppConstants, OIDCConfig

from .models import (
    AuthorizationGetRequest,
    AuthorizationRequest,
    ClientAuthorizationRegistry,
)

# from typing import Annotated


pp = pprint.PrettyPrinter(indent=4)


class LoggerFactory(Protocol):
    """TODO"""

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """TODO"""
        ...


class OIDCAuthorization:
    """TODO"""

    _app: FastAPI = None
    _router: APIRouter = None
    _oidc_config: OIDCConfig = None
    _client_registrar_module = None
    _authorization_request_registrar_module = None
    _logger: LoggerFactory = None

    # /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/gi;
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
            cls._client_registrar_module = importlib.import_module(
                oidc_config.module_config.configuration.client_endpoint.client_registrar_module
            )

            cls._authorization_request_registrar_module = importlib.import_module(
                oidc_config.module_config.configuration.authorization_endpoint.authorization_request_registrar_module
            )
            cls._logger = logger_factory.get_logger("OIDCAuthorization")

    @classmethod
    async def __validate_authorization_request(
        cls, authorization_request: AuthorizationGetRequest | AuthorizationRequest
    ):
        # if (authorization_request.state) {
        #     error_object.state = authorization_request.state;
        # }

        # if (authorization_request.nonce) {
        #     error_object.nonce = authorization_request.nonce;
        # }

        openid_scopes_found = (
            authorization_request.scope.split() if authorization_request.scope else []
        )
        if "openid" not in openid_scopes_found:
            message = "invalid scope, scope must include openid"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

        if (
            not authorization_request.response_type
            or authorization_request.response_type.strip() != "code"
        ):
            message = (
                "unsupported_response_type, Only Authorization Code Flow is supported."
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    @classmethod
    async def __verify_client_registration_entries(
        cls, authorization_request: AuthorizationGetRequest | AuthorizationRequest
    ) -> None:
        if (
            not authorization_request.client_id
            or not authorization_request.redirect_uri
        ):
            error_message = "Incorrect client_id/redirect_uri values."
            cls._logger.info(error_message)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=error_message
            )

        redirect_url = urlparse(authorization_request.redirect_uri)

        if redirect_url.scheme.lower() != "https":
            error_message = "Redirect_uri must use the https protocol."
            cls._logger.info(error_message)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=error_message
            )

        client_registry_dict = (
            await cls._client_registrar_module.get_client_registration(
                authorization_request.client_id
            )
        )

        client_registry = None
        if client_registry_dict:
            client_registry = ClientAuthorizationRegistry.parse_obj(
                client_registry_dict
            )

        if not client_registry:
            error_message = "Client (client_id) is not registered."
            cls._logger.info(error_message)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=error_message
            )

        client_registry_port = str(client_registry.redirect_uri_port.strip())
        if (
            client_registry_port
            and client_registry_port != "443"
            and client_registry_port != str(redirect_url.port)
        ):
            error_message = "Incorrect redirect_uri values - port mismatch."
            cls._logger.info(error_message)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=error_message
            )

        if client_registry.redirect_uri_hostname.strip() != redirect_url.hostname:
            error_message = (
                "Incorrect client_id/redirect_uri values - redirect hostname mismatch."
            )
            cls._logger.info(error_message)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=error_message
            )

        return

    @classmethod
    async def __process_authorization_request(
        cls, authorization_request: AuthorizationGetRequest | AuthorizationRequest
    ):
        """
        The first step in validating the authorizaion request is to verify that the
        the client_id and the redirect_uri match the ones in the client registry
        entry.  If this verification step fails, no reidrect should be sent.  this
        is essential to prevent reflected attacks.

        @param  {[type]} authorization_request [description]
        @return {[type]}                      [description]
        """
        await cls.__verify_client_registration_entries(authorization_request)
        #  Now that the client_id and redirect_uri are verified, we validate the
        #  authorization request and we can redirect with errors if any is found.

        await cls.__validate_authorization_request(authorization_request)
        authorization_request_as_dict = {}
        if isinstance(authorization_request, AuthorizationGetRequest):
            authorization_request_as_dict = asdict(authorization_request)
        else:
            authorization_request_as_dict = authorization_request.model_dump()

        authorization_request_as_dict["granted"] = True
        authorization_request_id = await cls._authorization_request_registrar_module.post_authorization_request(
            authorization_request_as_dict
        )

        #  Everything is good to proceed for End-User authentication & consent:
        temp_redirect_uri = (
            cls._oidc_config.module_config.configuration.user_info_endpoint.user_authentication_url
            + "?authorization_request_id="
            + quote(authorization_request_id)
        )

        response = RedirectResponse(url=temp_redirect_uri)
        # print(f"{temp_redirect_uri}")
        return response

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

        # registering the jwks endpoints
        @cls._router.get(
            "/authorize",
            tags=[" authorize "],
            summary="OIDC authorize GET implementation",
            response_class=RedirectResponse,
            status_code=302,
        )
        async def get_oidc_authorize(
            authorization_request: AuthorizationGetRequest = Depends(),
        ) -> dict[Any, Any]:
            response = await cls.__process_authorization_request(authorization_request)
            # print(f"{response=}")
            return response

        # registering the jwks x5c endpoint
        @cls._router.post(
            "/authorize",
            tags=[" authorize "],
            summary="OIDC authorize POST implementation",
            response_class=RedirectResponse,
        )
        async def post_oidc_authorize(
            authorization_request: AuthorizationRequest,
        ) -> dict[Any, Any]:
            # pp.pprint(authorization_request)
            response = await cls.__process_authorization_request(authorization_request)
            return response


async def configure_routes(
    app: FastAPI,
    router: APIRouter,
    oidc_config: OIDCConfig,
    logger_factory: Type[LoggerFactory],
):
    """TODO"""

    await OIDCAuthorization.configure_routes(
        app,
        router,
        oidc_config,
        logger_factory,
    )
