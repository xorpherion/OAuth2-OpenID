package com.bornium.security.oauth2openid;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class ConstantsTest {
    public static final String PROTOCOL = "http";
    public static final String HOST_LOCALHOST = PROTOCOL + "://localhost";

    public static final String HOST_AUTHORIZATION_SERVER = HOST_LOCALHOST;
    public static final int PORT_AUTHORIZATION_SERVER = 1337;
    public static final String URL_AUTHORIZATION_SERVER = HOST_AUTHORIZATION_SERVER + ":" + PORT_AUTHORIZATION_SERVER;
    public static final String SERVER_AUTHORIZATION_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_AUTHORIZATION;
    public static final String SERVER_DEVICE_AUTHORIZATION_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_DEVICE_AUTHORIZATION;
    public static final String SERVER_TOKEN_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_TOKEN;
    public static final String SERVER_USERINFO_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_USERINFO;
    public static final String SERVER_LOGIN_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_LOGIN;
    public static final String SERVER_CONSENT_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_CONSENT;
    public static final String SERVER_AFTER_LOGIN_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_AFTER_LOGIN;
    public static final String SERVER_REVOCATION_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_REVOCATION;
    public static final String SERVER_VERIFICATION_ENDPOINT = URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_VERIFICATION;

    public static final String HOST_CLIENT = HOST_LOCALHOST;
    public static final int PORT_CLIENT = 1338;
    public static final String URL_CLIENT = HOST_CLIENT + ":" + PORT_CLIENT;
    public static final String CLIENT_DEFAULT_REDIRECT_URI = URL_CLIENT + Constants.ENDPOINT_CLIENT_CALLBACK;
    public static final String CLIENT_DEFAULT_ID = "cid_123";
    public static final String CLIENT_DEFAULT_SECRET = "SECRET";
    public static final String CLIENT_DEFAULT_ID2 = "cid_456";
    public static final String CLIENT_DEFAULT_SECRET2 = "secret";
    public static final String CLIENT_DEFAULT_SCOPE = "profile phone";
    public static final String CLIENT_DEFAULT_SCOPE_OPENID = "openid " + CLIENT_DEFAULT_SCOPE;
    public static final String CLIENT_DEFAULT_STATE = "totallyRandomStateValue";
    public static final String CLIENT_DEFAULT_NONCE = "totallyRandomNonceValue";

    public static final String URL_PROTECTED_RESOURCE = URL_CLIENT + Constants.ENDPOINT_USERINFO;

    public static final String USER_DEFAULT_NAME = "Till";
    public static final String USER_DEFAULT_PASSWORD = "Born";

    public static final String CUSTOM_CLAIM_NAME = "CustomClaim";
    public static final String CUSTOM_CLAIM_VALUE = "CustomValue";
}
