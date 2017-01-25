package com.nogiax.security.oauth2openid;

import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.interceptor.Outcome;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServerInterceptor extends AbstractInterceptor {

    AuthorizationServer server;

    @Override
    public void init(Router router) throws Exception {
        super.init(router);
        server = new AuthorizationServer(new MembraneFunctionality());
    }

    @Override
    public Outcome handleRequest(Exchange exc) throws Exception {
        com.nogiax.http.Exchange newExc = Util.convertFromMembraneExchange(exc);
        server.invokeOn(newExc);
        exc.setResponse(Util.convertToMembraneExchange(newExc).getResponse());
        if(exc.getResponse().isUserError() || exc.getResponse().isServerError())
            return Outcome.RETURN;
        return Outcome.CONTINUE;
    }
}
