"""TODO"""
import logging
import pathlib
import pprint
# configure_routes as token_configure_routes
from typing import Any, Protocol, Type

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

from auth_utils.crypto import CryptoUtils

from authorization.routes import \
    configure_routes as authorization_configure_routes
from configuration.routes import configure_routes as config_configure_routes
from jwt_token.routes import configure_routes as jwt_token_configure_routes
from oidc_config import OIDCConfig
from user.routes import configure_routes as user_configure_routes

pp = pprint.PrettyPrinter(indent=4)


class LoggerFactory(Protocol):
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """TODO"""
        ...


async def configure_routes(
    app: FastAPI,
    router: APIRouter,
    module_config: dict[str, Any],
    logger_factory: Type[LoggerFactory],
) -> None:
    """TODO"""

    oidc_config = OIDCConfig.model_validate(module_config)

    print("\n\nconfiguring routes for oidc\n\n")
    # pp.pprint(module_config)
    await CryptoUtils.init_module(oidc_config)
    await config_configure_routes(app, router, oidc_config, logger_factory)
    await authorization_configure_routes(app, router, oidc_config, logger_factory)
    await jwt_token_configure_routes(app, router, oidc_config, logger_factory)
    await user_configure_routes(app, router, oidc_config, logger_factory)
