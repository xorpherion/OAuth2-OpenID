package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.security.oauth2openid.server.AuthorizationServer;

import java.util.function.Consumer;

public interface AuthenticationProvider {

    /**
     * Initiate authentication and consent by using the response of the exchange to redirect the user. The server
     * provides an id for that transaction. When authentication and consent is done (success or error on consent) the
     * callback should be called as the last action with that same ID in the LoginResult. The exchange in the
     * LoginResult should be the current running exchange. The response object will be overridden. Do not override the
     * response after calling the callback.
     * @param ctxId
     * @return
     */
    void initiateAuthenticationAndConsent(String ctxId, boolean skipConsentCheck, Exchange currentlyRunningExchange, AuthorizationServer server, Consumer<LoginResult> callback);
}
