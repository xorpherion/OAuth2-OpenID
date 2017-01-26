package com.nogiax.security.oauth2openid.client;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class OAuth2AuthorizationServerData {

    String authEndpoint;
    String tokenEndpoint;
    String userinfoEndpoint;

    public OAuth2AuthorizationServerData(String authEndpoint, String tokenEndpoint, String userinfoEndpoint) {
        this.authEndpoint = authEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getAuthEndpoint() {
        return authEndpoint;
    }

    public void setAuthEndpoint(String authEndpoint) {
        this.authEndpoint = authEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }
}
