package com.bornium.security.oauth2openid;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Constants {

    public static final String ENCODING_DEFAULT = "UTF-8";

    //Parameter names
    public static final String PARAMETER_RESPONSE_TYPE = "response_type";
    public static final String PARAMETER_CLIENT_ID = "client_id";
    public static final String PARAMETER_REDIRECT_URI = "redirect_uri";
    public static final String PARAMETER_SCOPE = "scope";
    public static final String PARAMETER_STATE = "state";
    public static final String PARAMETER_ERROR = "error";
    public static final String PARAMETER_CLAIMS = "claims";
    public static final String PARAMETER_CODE = "code";
    public static final String PARAMETER_GRANT_TYPE = "grant_type";
    public static final String PARAMETER_ACCESS_TOKEN = "access_token";
    public static final String PARAMETER_TOKEN_TYPE = "token_type";
    public static final String PARAMETER_EXPIRES_IN = "expires_in";
    public static final String PARAMETER_REFRESH_TOKEN = "refresh_token";
    public static final String PARAMETER_USERNAME = "username";
    public static final String PARAMETER_PASSWORD = "password";
    public static final String PARAMETER_TOKEN = "token";
    public static final String PARAMETER_PROMPT = "prompt";
    public static final String PARAMETER_RESPONSE_MODE = "response_mode";
    public static final String PARAMETER_REQUEST_URI = "request_uri";
    public static final String PARAMETER_REQUEST = "request";
    public static final String PARAMETER_AUTH_TIME = "auth_time";
    public static final String PARAMETER_NONCE = "nonce";
    public static final String PARAMETER_ID_TOKEN = "id_token";
    public static final String PARAMETER_MAX_AGE = "max_age";
    public static final String PARAMETER_ID_TOKEN_HINT = "id_token_hint";
    public static final String PARAMETER_LOGIN_HINT = "login_hin";
    public static final String PARAMETER_ACR_VALUES = "acr_values";
    public static final String PARAMETER_DISPLAY = "display";
    public static final String PARAMETER_UI_LOCALES = "ui_locales";
    public static final String PARAMETER_USER_CODE = "user_code";
    public static final String PARAMETER_DEVICE_CODE = "device_code";
    public static final String PARAMETER_VERIFICATION_URI = "verification_uri";
    public static final String PARAMETER_VERIFICATION_URI_COMPLETE = "verification_uri_complete";
    public static final String PARAMETER_INTERVAL = "interval";
    public static final String SESSION_ENDPOINT = "current_endpoint";

    //Scope names
    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_EMAIL = "email";
    public static final String SCOPE_PROFILE = "profile";
    public static final String SCOPE_ADDRESS = "address";
    public static final String SCOPE_PHONE = "phone";

    //Parameter values
    public static final String PARAMETER_VALUE_CODE = "code";
    public static final String PARAMETER_VALUE_TOKEN = "token";
    public static final String PARAMETER_VALUE_ID_TOKEN = "id_token";
    public static final String PARAMETER_VALUE_AUTHORIZATION_CODE = "authorization_code";
    public static final String PARAMETER_VALUE_PASSWORD = "password";
    public static final String PARAMETER_VALUE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String PARAMETER_VALUE_BEARER = "Bearer";
    public static final String PARAMETER_VALUE_REFRESH_TOKEN = "refresh_token";
    public static final String PARAMETER_VALUE_NONE = "none";
    public static final String PARAMETER_VALUE_LOGIN = "login";
    public static final String PARAMETER_VALUE_QUERY = "query";
    public static final String PARAMETER_VALUE_FRAGMENT = "fragment";
    public static final String PARAMETER_VALUE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";


    //Endpoint names
    public static final String ENDPOINT_AUTHORIZATION = "/auth";
    public static final String ENDPOINT_DEVICE_AUTHORIZATION = "/device_auth";
    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_USERINFO = "/userinfo";
    public static final String ENDPOINT_LOGIN = "/login/login";
    public static final String ENDPOINT_AFTER_LOGIN = "/auth2";
    public static final String ENDPOINT_CONSENT = "/login/consent";
    public static final String ENDPOINT_REVOCATION = "/revoke";
    public static final String ENDPOINT_JWK = "/jwk";
    public static final String ENDPOINT_VERIFICATION = "/verify";
    public static final String ENDPOINT_WELL_KNOWN = "/.well-known/openid-configuration";

    public static final String ENDPOINT_CLIENT_CALLBACK = "/oauth2cb";

    //Error values
    public static final String ERROR_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    public static final String ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String ERROR_INVALID_SCOPE = "invalid_scope";
    public static final String ERROR_INVALID_TOKEN = "invalid_token";
    public static final String ERROR_INVALID_GRANT = "invalid_grant";
    public static final String ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String ERROR_UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type";
    public static final String ERROR_INTERACTION_REQUIRED = "interaction_required";
    public static final String ERROR_REQUEST_URI_NOT_SUPPORTED = "request_uri_not_supported";
    public static final String ERROR_REQUEST_NOT_SUPPORTED = "request_not_supported";
    public static final String ERROR_INVALID_CLIENT = "invalid_client";
    public static final String ERROR_EXPIRED_TOKEN = "expired_token";
    public static final String ERROR_SLOW_DOWN = "slow_down";
    public static final String ERROR_AUTHORIZATION_PENDING = "authorization_pending";

    public static final String ERROR_COULD_NOT_VALIDATE_USER = "Could not verify user. Please try again.";
    public static final String ERROR_POSSIBLE_CSRF = "Possible CSRF attack.";

    //Session names
    public static final String SESSION_LOGGED_IN = "logged_in";
    public static final String SESSION_CONSENT_GIVEN = "consent_given";
    public static final String SESSION_LOGIN_STATE = "login_state";
    public static final String SESSION_REDIRECT_FROM_ERROR = "redirect_from_error";
    public static final String SESSION_AUTHORIZATION_CODE = "authorization_code";

    //Values
    public static final String VALUE_YES = "yes";
    public static final String VALUE_NO = "no";

    //Login names
    public static final String LOGIN_USERNAME = "username";
    public static final String LOGIN_PASSWORD = "password";
    public static final String LOGIN_CONSENT = "consent";

    // Header names
    public static final String HEADER_LOCATION = "Location";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_COOKIE = "Cookie";
    public static final String HEADER_CACHE_CONTROL = "Cache-Control";
    public static final String HEADER_PRAGMA = "Pragma";
    public static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
    public static final String HEADER_SET_COOKIE = "Set-Cookie";
    public static final String HEADER_X_FRAME_OPTIONS = "X-Frame-Options";
    public static final String HEADER_HOST = "Host";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";

    //Header values
    public static final String HEADER_VALUE_NO_CACHE = "no-cache";
    public static final String HEADER_VALUE_NO_STORE = "no-store";
    public static final String HEADER_VALUE_SAMEORIGIN = "SAMEORIGIN";
    public static final String HEADER_VALUE_CONTENT_TYPE_JSON = "application/json";

    // Response types
    public static final String TOKEN_TYPE_CODE = "code";
    public static final String TOKEN_TYPE_TOKEN = "token";
    public static final String TOKEN_TYPE_ID_TOKEN = "id_token";

    // Claim names
    public static final String CLAIM_SUB = "sub";
    public static final String CLAIM_NAME = "name";
    public static final String CLAIM_GIVEN_NAME = "given_name";
    public static final String CLAIM_FAMILY_NAME = "family_name";
    public static final String CLAIM_MIDDLE_NAME = "middle_name";
    public static final String CLAIM_NICKNAME = "nickname";
    public static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
    public static final String CLAIM_PROFILE = "profile";
    public static final String CLAIM_PICTURE = "picture";
    public static final String CLAIM_WEBSITE = "website";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_EMAIL_VERIFIED = "email_verified";
    public static final String CLAIM_GENDER = "gender";
    public static final String CLAIM_BIRTHDATE = "birthdate";
    public static final String CLAIM_ZONEINFO = "zoneinfo";
    public static final String CLAIM_LOCALE = "locale";
    public static final String CLAIM_PHONE_NUMBER = "phone_number";
    public static final String CLAIM_PHONE_NUMBER_VERIFIED = "phone_number_verified";
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_UPDATED_AT = "updated_at";
    public static final String CLAIM_ISS = "iss";
    public static final String CLAIM_AZP = "azp";
    public static final String CLAIM_IAT = "iat";
    public static final String CLAIM_AUD = "aud";

    // ID Token claims
    public static final String CLAIM_NONCE = "nonce";
    public static final String CLAIM_AUTH_TIME = "auth_time";
    public static final String CLAIM_AUTHORIZED_PARTY = "azp";
    public static final String CLAIM_AT_HASH = "at_hash";
    public static final String CLAIM_C_HASH = "c_hash";

    // Alg values
    public static final String ALG_SHA_256 = "SHA-256";


    public static final String CONTEXT_PATH = "context-path";
    public static final String GRANT_CONTEXT_ID = "grant_context_id";
}
