package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.predic8.membrane.annot.MCElement;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.interceptor.Outcome;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServerInterceptor extends AbstractInterceptor {

    AuthorizationServer server;
    ProvidedServices providedServices;


    @Override
    public void init(Router router) throws Exception {
        super.init(router);
        providedServices = new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER);
        server = new AuthorizationServer(providedServices);
    }

    @Override
    public Outcome handleRequest(Exchange exc) throws Exception {
        com.nogiax.http.Exchange newExc = new com.nogiax.http.Exchange(UtilMembrane.convertFromMembraneRequest(exc.getRequest()));
        newExc = server.invokeOn(newExc);
        exc.setResponse(UtilMembrane.convertToMembraneResponse(newExc.getResponse()));
        ((MembraneSessionProvider) providedServices.getSessionProvider()).postProcessSession(newExc, exc);
        return Outcome.RETURN;
    }
}
