package com.bornium.security.oauth2openid.server;

public class TokenContext {
    private final String clientId;

    public TokenContext(String clientId) {
        this.clientId = clientId;
    }

    public String getClientId() {
        return clientId;
    }
}
