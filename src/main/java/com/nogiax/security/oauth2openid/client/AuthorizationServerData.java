package com.nogiax.security.oauth2openid.client;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServerData {

    String authEndpoint;
    String tokenEndpoint;
    String userinfoEndpoint;

    public AuthorizationServerData(String authEndpoint, String tokenEndpoint, String userinfoEndpoint) {
        this.authEndpoint = authEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getAuthEndpoint() {
        return authEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }
}
