"""TODO"""
import logging
import pprint
from typing import Any, Protocol, Type

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from authorization.routes import configure_routes as authorization_config_routes
from configuration.routes import configure_routes as config_configure_routes

import sys
import os


import pathlib

pp = pprint.PrettyPrinter(indent=4)


class StaticContentModuleConfig(BaseModel):
    """TODO"""

    static_content_folder: str



class StaticContentConfig(BaseModel):
    """TODO"""
    module_name: str
    module_config: StaticContentModuleConfig


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

    pp.pprint(module_config)

    static_content_config = StaticContentConfig.model_validate(module_config)

    print("\n\nconfiguring routes for oidc\n\n")

    os.path.abspath(__file__)
    # pp.pprint(module_config)

    print(f'current working dir: {os.getcwd()} , sys_path: {sys.path}\n\n')

    print( f'{pathlib.Path(__file__).parent.resolve()=}\n\n')

    await app.mount(
        "/public",
        StaticFiles(directory=static_content_config.module_config.static_content_folder),
        name="static",
    )
