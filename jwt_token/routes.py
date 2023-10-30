""" TODO """

import base64
import importlib
import importlib.util
import logging
import pprint
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Protocol, Type

import jwt
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, status
# from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth_utils.crypto import CryptoUtils
from oidc_config import AppConstants, OIDCConfig

from .models import GrantTypeEnum, TokenRequestParams

pp = pprint.PrettyPrinter(indent=4)


authorization_header_pattern = re.compile(r"/(\S+)\s+(\S+)/")
basic_credentials_pattern = re.compile(r"/(\S+):(\S+)/")

basic_authorization = HTTPBasic()


class LoggerFactory(Protocol):
    """TODO"""

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """TODO"""
        ...


AUTH_HEADER_PARAM_AUTHORIZATION = "REQUIRED. Http header Authorization, must be of type 'Basic', containing the requester's credentials."


def _get_text_from_b64(b64_text: str) -> str:
    print(f"{b64_text=}")
    base64_bytes = b64_text.encode("utf8")
    text_string_bytes = base64.b64decode(base64_bytes)
    return text_string_bytes.decode("utf8")


async def _verify_and_get_token_request_params(
    request_params: TokenRequestParams,
) -> TokenRequestParams:
    # request_params.username = authorization_credentials.username
    # request_params.password = authorization_credentials.password

    if request_params.grant_type == GrantTypeEnum.AUTHORIZATION_CODE:
        # /**
        #  * grant_type "authorization_code":
        #  *
        #  * code
        #  *     REQUIRED.  The authorization code received from the
        #  *     authorization server.
        #  *
        #  * redirect_uri
        #  *     REQUIRED, if the "redirect_uri" parameter was included in the
        #  *     authorization request as described in Section 4.1.1, and their
        #  *     values MUST be identical.
        #  *
        #  * client_id
        #  *     REQUIRED, if the client is not authenticating with the
        #  *     authorization server as described in Section 3.2.1.
        #  *
        #  */

        if not request_params.code:
            raise HTTPException(
                status_code=400,
                detail="code is required for authorization_code grant_type",
            )

        if not request_params.redirect_uri:
            raise HTTPException(
                status_code=400,
                detail="redirect_uri is required for authorization_code grant_type",
            )

        if not request_params.client_id:
            raise HTTPException(
                status_code=400,
                detail="client_id is required for authorization_code grant_type",
            )
    elif request_params.grant_type == GrantTypeEnum.PASSWORD:
        # /**
        #  *
        #  * grant_type "password":
        #  *
        #  * username:
        #  *     REQUIRED.  The resource owner username.
        #  *
        #  * password:
        #  *     REQUIRED.  The resource owner password.
        #  *
        #  * scope:
        #  *     OPTIONAL.  The scope of the access request as described by Section 3.3.
        #  */

        if not request_params.username:
            raise HTTPException(
                status_code=400,
                detail="username is required for password grant_type",
            )

        if not request_params.password:
            raise HTTPException(
                status_code=400,
                detail="password is required for password grant_type",
            )

    elif request_params.grant_type == GrantTypeEnum.REFRESH_TOKEN:
        # /**
        #  * grant_type "refresh_token".
        #  *
        #  * refresh_token:
        #  *     REQUIRED.  The refresh token issued to the client.
        #  *
        #  * scope:
        #  *     OPTIONAL.  The scope of the access request as described by
        #  *         Section 3.3.  The requested scope MUST NOT include any scope
        #  *         not originally granted by the resource owner, and if omitted is
        #  *         treated as equal to the scope originally granted by the
        #  *         resource owner.
        #  *
        #  */
        if not request_params.refresh_token:
            raise HTTPException(
                status_code=400,
                detail="refresh_token is required for refresh_token grant_type",
            )

    return request_params


class OIDCToken:
    """TODO"""

    __app = None
    __router = None
    __private_key = ""
    __public_key = ""
    _client_registrar_module = None
    _authorization_request_registrar_module = None
    _user_account_registrar_module = None

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
        if not cls.__app:
            cls.__app = app
            cls.__router = router
            cls._oidc_config = oidc_config
            cls._logger = logger_factory.get_logger("OIDCToken")

            cls._client_registrar_module = importlib.import_module(
                oidc_config.module_config.configuration.client_endpoint.client_registrar_module
            )

            cls._authorization_request_registrar_module = importlib.import_module(
                oidc_config.module_config.configuration.authorization_endpoint.authorization_request_registrar_module
            )

            cls._user_account_registrar_module = importlib.import_module(
                oidc_config.module_config.configuration.user_info_endpoint.user_account_registrar_module
            )

            # load public key:
            with open(
                oidc_config.module_config.configuration.jwk.pub_key_file_name,
                "rt",
                encoding="utf-8",
            ) as k_f:
                # key_data = kf.read()
                public_key_text = k_f.read()
                cls.__public_key = public_key_text.encode("utf8")

            # load private key:
            with open(
                oidc_config.module_config.configuration.jwk.priv_key_file_name,
                "rt",
                encoding="utf-8",
            ) as k_f:
                # key_data = kf.read()
                private_key_text = k_f.read()
                cls.__private_key = private_key_text.encode("utf8")

    @classmethod
    async def get_jwt(
        cls,
        payload: dict[str, str],
    ):
        """TODO"""

        jwt_token = jwt.encode(payload, cls.__private_key, algorithm="RS256")
        print(f"\n\n{jwt_token=}\n\n")
        return jwt_token

    # @classmethod
    # def _process_token_request(cls):
    #     ...

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

        # registering the token endpoints
        @cls.__router.post(
            "/token",
            tags=["token"],
            summary="JWT endpoint",
        )
        async def process_token_request(
            authorization_credentials: Annotated[
                HTTPBasicCredentials, Depends(basic_authorization)
            ],
            request_params: TokenRequestParams,
            # authorization: Annotated[str | None, Header()] = None,
        ) -> dict:
            verified_params = await _verify_and_get_token_request_params(
                request_params,
            )

            if verified_params.grant_type == GrantTypeEnum.AUTHORIZATION_CODE:
                jwt_token = await OIDCToken.process_token_for_authorization_code(
                    verified_params,
                )
                return {
                    "status": "succeeded",
                    "token": jwt_token,
                }

            if verified_params.grant_type == GrantTypeEnum.REFRESH_TOKEN:
                jwt_token = await OIDCToken.process_token_for_refresh_token(
                    verified_params,
                )
                return {
                    "status": "succeeded",
                    "token": jwt_token,
                }

            if verified_params.grant_type == GrantTypeEnum.PASSWORD:
                jwt_token = await OIDCToken.process_token_for_password(
                    verified_params,
                )
                return {
                    "status": "succeeded",
                    "token": jwt_token,
                }

            return {
                "status": "succeeded",
            }

    @classmethod
    async def process_token_for_authorization_code(
        cls,
        request_params: TokenRequestParams,
    ):
        """TODO
        - check if the auth code is in db
        - verify redirect-uri matches what is in db
        - return jwt token with proper elements
        """
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail="Not implemented!")

    @classmethod
    async def process_token_for_refresh_token(
        cls,
        request_params: TokenRequestParams,
    ):
        """TODO
        - parse the refresh token and verify it
        - extract elements from refresh token
        - return new jwt token with proper elements
        """
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail="Not implemented!")

    @classmethod
    async def process_token_for_password(
        cls,
        request_params: TokenRequestParams,
    ) -> str:
        """TODO"""

        user_account = await cls._user_account_registrar_module.get_user_account(
            request_params.username,
        )

        if user_account:
            print(f"{user_account=}")
            # check if the password is correct
            encrypted_password = await CryptoUtils.encrypt_password(
                request_params.password,
            )

            print(f"{encrypted_password=}")
            if user_account["password"] == encrypted_password:
                jwt_payload = {
                    "sub": request_params.username,
                    "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=86400),
                }
                print(f"{jwt_payload=}")

                return await cls.get_jwt(jwt_payload)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="",
        )


async def configure_routes(
    app: FastAPI,
    router: APIRouter,
    oidc_config: OIDCConfig,
    logger_factory: Type[LoggerFactory],
):
    """TODO"""

    await OIDCToken.configure_routes(
        app,
        router,
        oidc_config,
        logger_factory,
    )
