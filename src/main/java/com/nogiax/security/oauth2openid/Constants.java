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

    //Scope names
    public static final String SCOPE_OPENID = "openid";

    //Parameter values
    public static final String PARAMETER_VALUE_CODE = "code";
    public static final String PARAMETER_VALUE_TOKEN = "token";
    public static final String PARAMETER_VALUE_PASSWORD = "password";
    public static final String PARAMETER_VALUE_CLIENT_CREDENTIALS = "client_credentials";

    //Endpoint names
    public static final String ENDPOINT_AUTHORIZATION = "/auth";
    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_USERINFO = "/userinfo";
    public static final String ENDPOINT_LOGIN = "/login/login";
    public static final String ENDPOINT_CONSENT = "/login/consent";

    public static final String ENDPOINT_CLIENT_CALLBACK = "/oauth2cb";

    //Error values
    public static final String ERROR_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    public static final String ERROR_INVALID_SCOPE = "invalid_scope";

    public static final String ERROR_COULD_NOT_VALIDATE_USER = "Could not verify user. Please try again.";
    public static final String ERROR_POSSIBLE_CSRF = "Possible CSRF attack.";

    //Session names
    public static final String SESSION_LOGGED_IN = "logged_in";
    public static final String SESSION_CONSENT_GIVEN = "consent_given";
    public static final String SESSION_LOGIN_STATE = "login_state";
    public static final String SESSION_REDIRECT_FROM_ERROR = "redirect_from_error";

    //Values
    public static final String VALUE_YES = "yes";
    public static final String VALUE_NO = "no";

    //Login names
    public static final String LOGIN_USERNAME = "username";
    public static final String LOGIN_PASSWORD = "password";
    public static final String LOGIN_CONSENT = "consent";

    // Grant type values
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";

    // Header names
    public static final String HEADER_LOCATION = "Location";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_COOKIE = "Cookie";

    public static final String TOKEN_TYPE_CODE = "code";
    public static final String TOKEN_TYPE_TOKEN = "token";
    public static final String TOKEN_TYPE_ID_TOKEN = "id_token";

    public static final String SESSION_AUTHORIZATION_CODE = "authorization_code";

    public static final String PARAMETER_VALUE_BEARER = "Bearer";


}
