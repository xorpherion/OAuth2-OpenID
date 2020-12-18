package com.bornium.security.oauth2openid.server.endpoints.login;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.endpoints.Endpoint;

public abstract class LoginEndpointBase extends Endpoint {
    public LoginEndpointBase(AuthorizationServer serverServices, String... paths) {
        super(serverServices, paths);
    }

    /**
     * Initiate authentification. The server provides an id for that transaction
     * @param ctxId
     * @return
     */
    public abstract Response initiateLoginAndConsent(String ctxId);

    /**
     * The server will ask for the id of the current running transaction. This should be the id given by initiateLoginAndConsent(...)
     * An idea to retain that id is to append it to all redirects as a query parameter
     * @param exc
     * @return
     */
    public abstract String getGrantContextId(Exchange exc);


    /**
     * Retrieve the authentication results for a given transaction
     * @param ctxId
     * @return
     */
    public abstract LoginResult getCurrentResultFor(String ctxId);
}
