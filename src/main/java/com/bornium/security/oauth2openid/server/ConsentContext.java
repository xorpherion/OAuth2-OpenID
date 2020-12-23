package com.bornium.security.oauth2openid.server;

import java.util.Set;

public class ConsentContext {
    String username;
    String clientId;
    boolean consented;
    Set<String> consentedScopesIfConsentGiven;

    public ConsentContext(String username, String clientId, Set<String> consentedScopesIfConsentGiven) {
        this(username,clientId,true, consentedScopesIfConsentGiven);
    }

    public ConsentContext(String username, String clientId, boolean consented, Set<String> consentedScopesIfConsentGiven) {
        this.username = username;
        this.clientId = clientId;
        this.consented = consented;
        this.consentedScopesIfConsentGiven = consentedScopesIfConsentGiven;
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

    public Set<String> getConsentedScopesIfConsentGiven() {
        return consentedScopesIfConsentGiven;
    }
}
