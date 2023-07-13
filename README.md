# openid_connect_fastapi

This module is an implementation of the core and discovery OpenID-Connect / OAuth 2.0 provider API.

**_Please Note That This module Is An Implementation Of The More Recent (Newer) Version Of OpenID: _OpenId Connect_, And It Does Not Support The Older OpenID 2.0_**. All OpenID 2.0-specific features, such as _realm_, are not supported. Furthermore, there is no plan for this module to support migration from the older OpenID 2.0 to the newer OpenID Connect.

**Release (>= 1.x.x)**. This release is compliant with the OpenID Connect / OAuth 2.0 [documentation](http://openid.net/connect/), and offers the following endpoint implementation:

1- _authorization endpoint_:

2- The [discovery](http://openid.net/specs/openid-connect-discovery-1_0.html) implementation of OpenID Connect is implemented. The specification implementation is comprised in the following endpoints:

- _JWKS endpoint_: for retrieval of public key
- _JWKS_X5C endpoint_: for retrieval of public X5C certificate
- _/.well-known/openid-configuration endpoint_: for a JSON documentation of the entire _discovery API_ implementation.

3- The _token endpoint_ implementation covers:

- _Authorization Code Grant Type_
- _Resource Owner Password Credentials Grant Type_

4- The _user_info_ endpoint:

- The _signin_ (_login_) function is implemented to fully support redirects as per the OpenID Connect specification for the _Authorization Code Request_. The implementation requires/depends on the _FastAPI cookie_ plugin.
- The _signout_ function is implemented

# Limitations of The Current Release

- Client dynamic registration IS NOT INCLUDED", it is left to the user to implement
- Only authorization code flow request is implemented
- The token endpoint DOES NOT IMPLEMENT the *Refresh Token Grant Type*

# Usage

## Sample Application

The application using this module: 

1. uses mongoDB for persistence of authorization requests, and tokens.

1. relies on another service instance (e.g. nginx) for termination of the SSL connections

1. relies on _mongoDB_ indexes ("expireAfter" indexes) for automatic deletion of expired tokens.


## Configuration


```javascript
  let hapi_openid_connect = require("openid_connect_fastapi");

  ...
  server.register(hapi_openid_connect, oidc_options, callback);
  ...
```

Where _oidc_options_ is a json configuration object as follows:

```yaml
    issuer: https://localhost/saoidc
    issuer_audience: r3b9c15a1U74A68114x2
    scopes_supported: 
    - profile
    - address
    - email
    - phone
    jwk: 
        cert_type_rsa: true
        priv_key_file_name: ./config/oidc/sampleapp-key.pem
        pub_key_file_name: ./config/oidc/sampleapp-cert.pem
        cert_chain_file_name: ./config/oidc/sampleapp-cert-chain.pem

    authorization_endpoint: 
        authorization_request_registrar_module: /lib/authorization_request_registrar_module

    token_endpoint: 
        token_registrar_module: /lib/token_registrar_module
        authorization_code_grant_type: 
            token_duration_seconds: 600
        
        password_grant_type: 
            token_duration_seconds: 900
        

    user_info_endpoint: 
        user_authentication_url: https://localhost/saoidc/signin
        user_post_login_account_url: https://localhost/sa/accountii
        user_account_registrar_module: /lib/user_account_registrar_module

    client_endpoint: 
        client_registrar_module: lib.client_registrar_module
```

### Configuration Attributes

Most of the attributes in the json configuration object are self-explanatory, and the _registrar_ ones are described as follows:

#### authorization_endpoint

- **authorization_request_registrar_module**: This attribute is a path to a _python_ module which will be _imported_ by the openid_connect_fastapi code. The registrar module must export the following functions, **_which must be async def functions**:

  1- _put_authorization_request(authorization_request)_ which must update the authorization_request object in the persistence store.

  2- _get_authorization_request(authorization_request_id)_ which must retrieve the authorization_request associated with the authorization_request_id argument from the persistence store.

  3- _post_authorization_request(authorization_request)_ which must persist the authorization_request object, and return an id for it.

  4- _delete_authorization_request(authorization_request_id)_ which must delete the authorization request from the persistence store

#### token_endpoint

- **token_registrar_module**: This attribute is a path to a _python_ module which will be _imported_ by the openid_connect_fastapi code. This registrar module must to export the following functions, **_which must be async def functions**:

  1- _put_token(oidc_token)_ which must update the oidc_token object in the psersistence store.

  2- _get_token(oidc_token_id)_ which must retrieve the oidc_token associated with the oidc_token_id argument from the persistence store. The oidc_token_id is also used as the access_token.

  3- _post_token(oidc_token)_ which must persist the oidc_token object, and return an id for it.

  4- _delete_token(oidc_token_id)_ which must delete the oidc_token request from the persistence store.

#### usrer_info_endpoint

- _user_authentication_url_: this is the **_https_** URL for the end_user authentication page (signin or login page).
- _user_post_login_account_url_: this is the **_https_** URL for the end_user account page (after signin or login page).

- **user_account_registrar_module**: This attribute is a path to a _python_ module which will be _imported_ by the openid_connect_fastapi code. This registrar module must export the following functions, **_which must be async def functions**:

  - _get_user_account_id_for_credentials(username, password)_:

    - verify that the username and password match a user account record
    - if the user account is found, set the _hapi-auth-cookie_ session cookie for the request if not already set.
    - return a Promise that must resolve with the user account id (the id is a unique string for the respective user account)
    - reject the Promise if the user account does not exist, or the credentials provided do not match.

    The returned user account id must be a string, and it must be less than 255 characters (as per the OpenID specs).

#### client_endpoint

- **client_registrar_module**: This attribute is a path to a _python_ module which will be _imported_ by the openid_connect_fastapi code. This registrar module must exports the following functions, **_which must be async def functions**:

  - _get_client_registration(clientId)_: This method must return a Promise which resolves to the client registration entry from a persistent store. The client registration entry must at least have the following attributes:

    - redirect_uri_hostname
    - redirect_uri_port
    - redirect_uri_path, and
    - description, which describes the permissions the client is requesting.

  - _get_client_account_id_for_credentials(username, password)_:

    - verify that the username and password match a client account record
    - return a Promise that must resolve with the client account id (the id is a unique string for the respective client account)
    - reject the Promise if the client account does not exist, or the credentials provided do not match.

    The returned/resolved user account id must be a string, and it must be less than 255 characters (as per the OpenID specs).

  - _process_signin_request(request, h)_:

    - verify that the username and password match a client account record
    - setup the session state to reflect signed in state if an account is found for the credentials in request.payload.username and request.payload.password
    - return a Promise that must resolve with the client account id (the id is a unique string for the respective client account)
    - reject the Promise if the client account does not exist, or the credentials provided in request.payload do not match.

    The returned/resolved user account id must be a string, and it must be less than 255 characters (as per the OpenID specs).
