"""TODO"""
import logging
import pprint
from typing import Any, Protocol, Type

from fastapi import APIRouter, FastAPI

from authorization.routes import \
    configure_routes as authorization_config_routes
from config.routes import configure_routes as config_configure_routes
from oidc_config import OIDCConfig

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

    # pp.pprint(module_config)

    oidc_config = OIDCConfig.parse_obj(module_config)

    print("\n\nconfiguring routes for oidc\n\n")
    # pp.pprint(module_config)
    await config_configure_routes(app, router, oidc_config, logger_factory)
    await authorization_config_routes(app, router, oidc_config, logger_factory)
