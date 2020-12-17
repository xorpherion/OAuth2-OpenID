package com.bornium.security.oauth2openid.server.endpoints.login;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.endpoints.Endpoint;

public abstract class LoginEndpointBase extends Endpoint {
    public LoginEndpointBase(AuthorizationServer serverServices, String... paths) {
        super(serverServices, paths);
    }

    public abstract Response initiateLoginAndConsent(String ctxId);
    public abstract String getGrantContextId(Exchange exc);
    public abstract LoginResult getCurrentResultFor(String ctxId);
}
