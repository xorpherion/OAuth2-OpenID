package com.nogiax.security.oauth2openid;

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

    //Endpoint names
    public static final String ENDPOINT_AUTHORIZATION = "/auth";
    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_USERINFO = "/userinfo";
    public static final String ENDPOINT_LOGIN = "/login/login";
    public static final String ENDPOINT_AFTER_LOGIN = "/auth2";
    public static final String ENDPOINT_CONSENT = "/login/consent";

    public static final String ENDPOINT_CLIENT_CALLBACK = "/oauth2cb";

    //Error values
    public static final String ERROR_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    public static final String ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String ERROR_INVALID_SCOPE = "invalid_scope";
    public static final String ERROR_INVALID_TOKEN = "invalid_token";
    public static final String ERROR_INVALID_GRANT = "invalid_grant";
    public static final String ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

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

    //Header values
    public static final String HEADER_VALUE_NO_CACHE = "no-cache";
    public static final String HEADER_VALUE_NO_STORE = "no-store";

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



}
