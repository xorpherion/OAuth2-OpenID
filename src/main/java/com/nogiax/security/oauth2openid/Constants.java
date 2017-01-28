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

    //Scope names
    public static final String SCOPE_OPENID = "openid";

    //Grant names
    public static final String GRANT_CODE = "code";
    public static final String GRANT_TOKEN = "token";
    public static final String GRANT_ID_TOKEN = "id_token";
    public static final String GRANT_PASSWORD = "password";
    public static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";

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


}
