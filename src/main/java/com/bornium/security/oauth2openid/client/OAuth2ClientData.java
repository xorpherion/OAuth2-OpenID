package com.bornium.security.oauth2openid.client;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class OAuth2ClientData {

    String clientId;
    String clientSecret;
    String responseType;
    String redirectUri;
    String scope;

    public OAuth2ClientData(String clientId, String clientSecret, String responseType, String redirectUri, String scope) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.responseType = responseType;
        this.redirectUri = redirectUri;
        this.scope = scope;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
