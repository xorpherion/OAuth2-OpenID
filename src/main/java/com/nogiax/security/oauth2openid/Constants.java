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
    public static final String OAUTH2_GRANT_CODE = "code";

    //Endpoint names
    public static final String ENDPOINT_AUTHORIZATION = "/auth";
    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_USERINFO = "/userinfo";
    public static final String ENDPOINT_LOGIN = "/login/login";
    public static final String ENDPOINT_CONSENT = "/login/consent";

    public static final String ENDPOINT_CLIENT_CALLBACK = "/oauth2cb";

    //Error values
    public static final String ERROR_INVALID_REQUEST = "invalid_request";

    //Session names
    public static final String SESSION_LOGGED_IN = "logged_in";
    public static final String SESSION_CONSENT_GIVEN = "consent_given";

    //Values
    public static final String VALUE_YES = "yes";
    public static final String VALUE_NO = "no";

    //Login names
    public static final String LOGIN_USERNAME = "username";
    public static final String LOGIN_PASSWORD = "password";
}
