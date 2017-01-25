package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.client.WebApplicationClient;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.interceptor.Outcome;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class WebApplicationClientInterceptor extends AbstractInterceptor {

    WebApplicationClient client;

    @Override
    public void init(Router router) throws Exception {
        super.init(router);
        client = new WebApplicationClient(new MembraneClientFunctionality());
    }

    @Override
    public Outcome handleRequest(Exchange exc) throws Exception {
        com.nogiax.http.Exchange newExc = new com.nogiax.http.Exchange(Util.convertFromMembraneRequest(exc.getRequest()));
        client.invokeOn(newExc);
        exc.setResponse(Util.convertToMembraneResponse(newExc.getResponse()));
        if(exc.getResponse() == null || exc.getResponse().isUserError() || exc.getResponse().isServerError())
            return Outcome.RETURN;
        return Outcome.CONTINUE;
    }
}
