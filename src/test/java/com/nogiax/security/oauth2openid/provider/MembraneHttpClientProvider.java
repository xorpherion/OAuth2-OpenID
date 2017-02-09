package com.nogiax.security.oauth2openid.provider;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.UtilMembrane;
import com.nogiax.security.oauth2openid.providers.HttpClientProvider;
import com.predic8.membrane.core.config.security.SSLParser;
import com.predic8.membrane.core.resolver.ResolverMap;
import com.predic8.membrane.core.transport.http.HttpClient;
import com.predic8.membrane.core.transport.ssl.SSLContext;
import com.predic8.membrane.core.transport.ssl.StaticSSLContext;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MembraneHttpClientProvider implements HttpClientProvider {

    HttpClient client;
    SSLContext ctx;

    public MembraneHttpClientProvider() {
        ctx = UtilMembrane.doNotValidateSSLCertificate();
        client = new HttpClient();
    }

    @Override
    public Exchange sendExchange(Exchange exc) throws Exception {
        com.predic8.membrane.core.exchange.Exchange memExc = new com.predic8.membrane.core.exchange.Exchange(null);
        memExc.setRequest(UtilMembrane.convertToMembraneRequest(exc.getRequest()));
        memExc.getDestinations().add(memExc.getRequest().getUri());
        memExc.setProperty(com.predic8.membrane.core.exchange.Exchange.SSL_CONTEXT,ctx);
        com.predic8.membrane.core.exchange.Exchange memRespExc = client.call(memExc);
        exc.setResponse(UtilMembrane.convertFromMembraneResponse(memRespExc.getResponse()));
        return exc;
    }
}
