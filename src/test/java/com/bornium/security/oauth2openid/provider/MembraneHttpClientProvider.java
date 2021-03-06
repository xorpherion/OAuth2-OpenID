package com.bornium.security.oauth2openid.provider;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Convert;
import com.bornium.security.oauth2openid.UtilMembrane;
import com.bornium.security.oauth2openid.providers.HttpClientProvider;
import com.predic8.membrane.core.transport.http.HttpClient;
import com.predic8.membrane.core.transport.ssl.SSLContext;

import java.net.URI;

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
        memExc.setRequest(Convert.convertToMembraneRequest(exc.getRequest()));
        String uri = "";
        if (!new URI(memExc.getRequest().getUri()).isAbsolute())
            uri = ConstantsTest.PROTOCOL + "://" + exc.getRequest().getHeader().getValue(Constants.HEADER_HOST);
        uri += memExc.getRequest().getUri();
        memExc.getDestinations().add(uri);
        memExc.setProperty(com.predic8.membrane.core.exchange.Exchange.SSL_CONTEXT, ctx);
        com.predic8.membrane.core.exchange.Exchange memRespExc = client.call(memExc);
        exc.setResponse(Convert.convertFromMembraneResponse(memRespExc.getResponse()));
        return exc;
    }
}
