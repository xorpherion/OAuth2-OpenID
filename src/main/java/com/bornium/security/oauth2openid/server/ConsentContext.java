package com.bornium.security.oauth2openid.server;

import java.util.Set;

public class ConsentContext {
    String username;
    String clientId;
    boolean consented;
    Set<String> consentedScopes;

    public ConsentContext(String username, String clientId, Set<String> consentedScopes) {
        this(username,clientId,true,consentedScopes);
    }

    public ConsentContext(String username, String clientId, boolean consented, Set<String> consentedScopes) {
        this.username = username;
        this.clientId = clientId;
        this.consented = consented;
        this.consentedScopes = consentedScopes;
    }

    public String getUsername() {
        return username;
    }

    public String getClientId() {
        return clientId;
    }

    public boolean isConsented() {
        return consented;
    }

    public Set<String> getConsentedScopes() {
        return consentedScopes;
    }
}
