package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.interceptor.Outcome;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServerInterceptor extends AbstractInterceptor {

    AuthorizationServer server;
    ServerProvider serverProvider;


    @Override
    public void init(Router router) throws Exception {
        super.init(router);
        serverProvider = new MembraneServerFunctionality();
        server = new AuthorizationServer(serverProvider);
    }

    @Override
    public Outcome handleRequest(Exchange exc) throws Exception {
        com.nogiax.http.Exchange newExc = new com.nogiax.http.Exchange(Util.convertFromMembraneRequest(exc.getRequest()));
        newExc = server.invokeOn(newExc);
        exc.setResponse(Util.convertToMembraneResponse(newExc.getResponse()));
        ((MembraneSessionProvider) serverProvider.getSessionProvider()).postProcessSession(newExc, exc);
        return Outcome.RETURN;
    }
}
