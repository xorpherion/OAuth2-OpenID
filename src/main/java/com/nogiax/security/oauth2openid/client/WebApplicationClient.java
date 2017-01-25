package com.nogiax.security.oauth2openid.client;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ClientProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class WebApplicationClient {
    Logger log = LoggerFactory.getLogger(WebApplicationClient.class);

    private final ClientProvider clientProvider;

    public WebApplicationClient(ClientProvider clientProvider) {
        this.clientProvider = clientProvider;
    }

    public Exchange invokeOn(Exchange exc) {
        log.info("Invoked " + WebApplicationClient.class.getSimpleName());
        return null;
    }
}
