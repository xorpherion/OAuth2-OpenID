package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.client.WebApplicationClient;
import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.interceptor.Outcome;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class WebApplicationClientInterceptor extends AbstractInterceptor {

    WebApplicationClient client;
    ClientProvider clientProvider;

    @Override
    public void init(Router router) throws Exception {
        super.init(router);
        clientProvider = new MembraneClientFunctionality();
        client = new WebApplicationClient(clientProvider, UtilMembrane.getDefaultCodeGrantClientData(), UtilMembrane.getDefaultAuthorizationServerData());
    }

    @Override
    public Outcome handleRequest(Exchange exc) throws Exception {
        com.nogiax.http.Exchange newExc = new com.nogiax.http.Exchange(UtilMembrane.convertFromMembraneRequest(exc.getRequest()));
        newExc = client.invokeOn(newExc);
        exc.setRequest(UtilMembrane.convertToMembraneRequest(newExc.getRequest()));
        exc.setResponse(UtilMembrane.convertToMembraneResponse(newExc.getResponse()));
        fixMembraneExchange(exc);
        ((MembraneSessionProvider) clientProvider.getSessionProvider()).postProcessSession(newExc, exc);
        if (exc.getResponse() != null)
            return Outcome.RETURN;
        return Outcome.CONTINUE;
    }

    private void fixMembraneExchange(Exchange exc) throws URISyntaxException {
        // this is only needed as the membrane exchange has additional meta data that is lost in converting only requests/responses
        URI origUri = new URI(exc.getRequest().getUri());
        exc.setOriginalRequestUri(exc.getRequest().getUri());
        String destination = exc.getDestinations().get(0);
        URI uri = new URI(exc.getDestinations().get(0));
        if(uri.getQuery() != null)
            destination = destination.replace(uri.getQuery(),origUri.getQuery() != null ? origUri.getQuery() : "");
        if(uri.getPath() != null)
            destination = destination.replace(uri.getPath(),origUri.getPath() != null ? origUri.getPath() : "/");
        exc.getDestinations().clear();
        exc.getDestinations().add(destination);
    }
}
