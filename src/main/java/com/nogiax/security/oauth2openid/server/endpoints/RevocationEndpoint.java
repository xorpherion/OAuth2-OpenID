package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;

/**
 * Created by Xorpherion on 07.02.2017.
 */
public class RevocationEndpoint extends Endpoint {
    public RevocationEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_REVOCATION);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        // token holen
        // im token gucken ob public oder confidential
        // je nachdem client auth
        // überprüfen ob token für client id
        // token expiren -> cascade children
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
