"""TODO"""
from pydantic import BaseModel


class JWKConfig(BaseModel):
    """TODO"""

    cert_type_rsa: bool
    priv_key_file_name: str
    pub_key_file_name: str
    pub_cert_file_name: str
    cert_chain_file_name: str


class AuthorizationEndpointConfig(BaseModel):
    """TODO"""

    authorization_request_registrar_module: str


class AuthorizationCodeGrantTypeConfig(BaseModel):
    """TODO"""

    token_duration_seconds: int


class PasswordGrantTypeConfig(BaseModel):
    """TODO"""

    token_duration_seconds: int


class TokenEndpointConfig(BaseModel):
    """TODO"""

    token_registrar_module: str
    authorization_code_grant_type: AuthorizationCodeGrantTypeConfig
    password_grant_type: PasswordGrantTypeConfig


class UserInfoEndpointConfig(BaseModel):
    """TODO"""

    user_authentication_url: str
    user_post_login_account_url: str
    user_account_registrar_module: str


class ClientEndpointConfig(BaseModel):
    """TODO"""

    client_registrar_module: str

class OIDCVaultKeeper(BaseModel):
    """TODO"""
    handshake: str
    encryption_key: str
    hmac_key: str


class OIDCModuleConfigConfiguration(BaseModel):
    """TODO"""

    issuer: str
    issuer_audience: str
    scopes_supported: list[str]
    jwk: JWKConfig
    authorization_endpoint: AuthorizationEndpointConfig
    token_endpoint: TokenEndpointConfig
    user_info_endpoint: UserInfoEndpointConfig
    client_endpoint: ClientEndpointConfig
    vault_keeper: OIDCVaultKeeper


class OIDCModuleConfig(BaseModel):
    """TODO"""

    oidc_url_path: str
    version: str
    configuration: OIDCModuleConfigConfiguration


class OIDCConfig(BaseModel):
    """TODO"""

    module_name: str
    module_config: OIDCModuleConfig


class AppConstants:
    """TODO"""

    AUTHORIZATION_ENDPOINT = "/authorize"
    TOKEN_ENDPOINT = "/token"
    USERINFO_ENDPOINT = "/userinfo"
    JWKS_ENDPOINT = "/jwks"
    JWKS_X5C_ENDPOINT = "/jwks/x5c"
