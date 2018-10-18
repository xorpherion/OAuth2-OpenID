package com.bornium.security.oauth2openid;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class Client {

    String clientId;
    String clientSecret;
    String redirectUri;
    boolean isConfidential;

    public Client(String clientId, String clientSecret, String redirectUri) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;

        if (clientSecret == null)
            isConfidential = false;
        else
            isConfidential = true;
    }

    public Client(String clientId, String redirectUri) {
        this(clientId, null, redirectUri);
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
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

    public boolean isConfidential() {
        return isConfidential;
    }

    public void setConfidential(boolean confidential) {
        isConfidential = confidential;
    }
}
