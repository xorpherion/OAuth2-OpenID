package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.server.ConsentContext;

import java.util.Optional;
import java.util.Set;

public class LoginResult {

    String grantContextId;
    Optional<String> authenticatedUser;
    ConsentContext consentContext;


    /**
     * The response on this exchange will be overridden by the callback to ensure a correct redirect as a follow up to the authentication event
     * Do not override the response after calling the callback
     */
    Exchange currentRunningExchange;

    public LoginResult(String grantContextId, Optional<String> authenticatedUser, ConsentContext consentContext, Exchange currentRunningExchange) {
        this.grantContextId = grantContextId;
        this.authenticatedUser = authenticatedUser;
        this.consentContext = consentContext;
        this.currentRunningExchange = currentRunningExchange;
    }

    public String getGrantContextId() {
        return grantContextId;
    }

    public Optional<String> getAuthenticatedUser() {
        return authenticatedUser;
    }

    public ConsentContext getConsentContext() {
        return consentContext;
    }

    public Exchange getCurrentRunningExchange() {
        return currentRunningExchange;
    }
}
