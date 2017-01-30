package com.nogiax.security.oauth2openid.provider;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.UtilMembrane;
import com.nogiax.security.oauth2openid.providers.HttpClientProvider;
import com.predic8.membrane.core.transport.http.HttpClient;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MembraneHttpClientProvider implements HttpClientProvider {

    HttpClient client;

    public MembraneHttpClientProvider() {
        client = new HttpClient();
    }

    @Override
    public Exchange sendExchange(Exchange exc) throws Exception {
        com.predic8.membrane.core.exchange.Exchange memExc = new com.predic8.membrane.core.exchange.Exchange(null);
        memExc.setRequest(UtilMembrane.convertToMembraneRequest(exc.getRequest()));
        memExc.getDestinations().add(memExc.getRequest().getUri());
        com.predic8.membrane.core.exchange.Exchange memRespExc = client.call(memExc);
        exc.setResponse(UtilMembrane.convertFromMembraneResponse(memRespExc.getResponse()));
        return exc;
    }
}
