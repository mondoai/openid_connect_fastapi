"""TODO"""
import logging
import pprint
from typing import Protocol, Type

from fastapi import APIRouter, FastAPI
from fastapi.responses import PlainTextResponse
from jwcrypto import jwk

from oidc_config import AppConstants, OIDCConfig

pp = pprint.PrettyPrinter(indent=4)


class LoggerFactory(Protocol):
    """TODO"""

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """TODO"""
        ...


class JWKConfig:
    """TODO"""

    __private_key = ""
    __public_cert = ""
    __public_key = ""
    __oidc_configuration = {}

    __public_jwk = None
    __app = None
    __router = None
    __logger = None

    def __init__(self, app: FastAPI, oidc_config: OIDCConfig):
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
            cls.__logger = logger_factory.get_logger("JWKConfig")

            cls.__oidc_configuration = {
                # REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
                # If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger.
                # This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
                "issuer": oidc_config.module_config.configuration.issuer,
                # REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
                "authorization_endpoint": f"{oidc_config.module_config.configuration.issuer}{AppConstants.AUTHORIZATION_ENDPOINT}",
                # URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
                "token_endpoint": f"{oidc_config.module_config.configuration.issuer}{AppConstants.TOKEN_ENDPOINT}",
                # RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY
                # contain port, path, and query parameter components.
                "userinfo_endpoint": f"{oidc_config.module_config.configuration.issuer}{AppConstants.USERINFO_ENDPOINT}",
                # REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to
                # validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used
                # by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use
                # (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended
                # usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so
                # is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations
                # of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
                "jwks_uri": f"{oidc_config.module_config.configuration.issuer}{AppConstants.JWKS_ENDPOINT}",
                # RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
                # "registration_endpoint": "",
                # RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
                # The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope
                # values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
                "scopes_supported": oidc_config.module_config.configuration.scopes_supported,
                # REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic
                # OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
                "response_types_supported": ["code"],
                # OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as
                # specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default
                # for Dynamic OpenID Providers is ["query", "fragment"].
                "response_modes_supported": ["query"],
                # OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic
                # OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other
                # Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
                "grant_types_supported": ["authorization_code"],
                # OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
                # "acr_values_supported": "",
                # REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types
                # include pairwise and public.
                "subject_types_supported": ["public"],
                # REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the
                # ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be
                # supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization
                # Endpoint (such as when using the Authorization Code Flow).
                "id_token_signing_alg_values_supported": ["RS256"],
                # OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for
                # the ID Token to encode the Claims in a JWT [JWT].
                "id_token_encryption_alg_values_supported": ["RS256"],
                # OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for
                # the ID Token to encode the Claims in a JWT [JWT].
                # "id_token_encryption_enc_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the
                # UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
                # "userinfo_signing_alg_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by
                # the UserInfo Endpoint to encode the Claims in a JWT [JWT].
                # "userinfo_encryption_alg_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the
                # UserInfo Endpoint to encode the Claims in a JWT [JWT].
                # "userinfo_encryption_enc_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for
                # Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. These
                # algorithms are used both when the Request Object is passed by value (using the request parameter) and when
                # it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
                # "request_object_signing_alg_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for
                # Request Objects. These algorithms are used both when the Request Object is passed by value and when it is
                # passed by reference.
                # "request_object_encryption_alg_values_supported": "",
                # OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for
                # Request Objects. These algorithms are used both when the Request Object is passed by value and when it is
                # passed by reference.
                # "request_object_encryption_enc_values_supported": "",
                # OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
                # The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described
                # in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by
                # extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified
                # in Section 2.3.1 of OAuth 2.0 [RFC6749].
                # "token_endpoint_auth_methods_supported": "",
                # OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token
                # Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the
                # private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The value none
                # MUST NOT be used.
                # "token_endpoint_auth_signing_alg_values_supported": "",
                # OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports.
                # These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
                # "display_values_supported": "",
                # OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types
                # are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification
                # are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
                "claim_types_supported": ["normal"],
                # OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when
                # using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration,
                # then information on how to register Clients needs to be provided in this documentation.
                # "service_documentation": "",
                # OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of
                # BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim
                # values.
                # "claims_locales_supported": "",
                # OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47
                # [RFC5646] language tag values.
                # "ui_locales_supported": "",
                # OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating
                # support. If omitted, the default value is false.
                # "claims_parameter_supported": "",
                # OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating
                # support. If omitted, the default value is false.
                # "request_parameter_supported": "",
                # OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true
                # indicating support. If omitted, the default value is true.
                # "request_uri_parameter_supported": "",
                # OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
                # using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If
                # omitted, the default value is false.
                # "require_request_uri_registration": "",
                # OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's
                # requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD
                # display this URL to the person registering the Client if it is given.
                # "op_policy_uri": "",
                # OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID
                # Provider's terms of service. The registration process SHOULD display this URL to the person registering the
                # Client if it is given.
                # "op_tos_uri": ""
                # RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be
                # able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
                "claims_supported": ["iss", "sub", "aud", "exp", "iat", "jti"],
            }

            # load public key:
            with open(
                oidc_config.module_config.configuration.jwk.pub_key_file_name,
                "rt",
                encoding="utf-8",
            ) as k_f:
                cls.__public_key = k_f.read()

            # load public cert:
            with open(
                oidc_config.module_config.configuration.jwk.pub_cert_file_name,
                "rt",
                encoding="utf-8",
            ) as k_f:
                # key_data = kf.read()
                cls.__public_cert = k_f.read()
                cls.__public_jwk = jwk.JWK.from_pem(cls.__public_cert.encode("utf-8"))

            # load priv key:
            with open(
                oidc_config.module_config.configuration.jwk.priv_key_file_name,
                "rt",
                encoding="utf-8",
            ) as k_f:
                # key_data = kf.read()
                cls.__private_key = k_f.read()

    @classmethod
    async def configure_routes(
        cls,
        app: FastAPI,
        router: APIRouter,
        oidc_config: OIDCConfig,
        logger_factory: Type[LoggerFactory],
    ):
        """TODO"""

        cls._init_module(app, router, oidc_config, logger_factory)

        # registering the jwks endpoints
        @cls.__router.get(
            "/jwks",
            tags=[" jwks "],
            summary="Returns the server's JWKS",
        )
        async def get_jwks() -> dict:
            return {"keys": [cls.__public_jwk]}

        # registering the jwks x5c endpoint
        @cls.__router.get(
            "/jwks/x5c",
            tags=[" jwks "],
            summary="Returns the server's X5C cerrificate",
            response_class=PlainTextResponse,
        )
        async def get_jwks_x5c() -> str:
            return cls.__public_cert


        # registering the jwks public key endpoint
        @cls.__router.get(
            "/jwks/public_key",
            tags=[" jwks "],
            summary="Returns the server's X5C cerrificate",
            response_class=PlainTextResponse,
        )
        async def get_jwks_public_key() -> str:
            return cls.__public_key


        @cls.__router.get(
            "/.well-known/openid-configuration",
            tags=["discovery"],
            summary="OpenID-Connect discovery endpoint",
        )
        async def get_well_known_spec() -> dict:
            return cls.__oidc_configuration


async def configure_routes(
    app: FastAPI,
    router: APIRouter,
    oidc_config: OIDCConfig,
    logger_fatory: Type[LoggerFactory],
):
    """TODO"""

    await JWKConfig.configure_routes(
        app,
        router,
        oidc_config,
        logger_fatory,
    )
