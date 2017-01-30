package com.nogiax.security.oauth2openid.server;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ProvidedServices;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.server.endpoints.AuthorizationEndpoint;
import com.nogiax.security.oauth2openid.server.endpoints.Endpoint;
import com.nogiax.security.oauth2openid.server.endpoints.LoginEndpoint;
import com.nogiax.security.oauth2openid.server.endpoints.TokenEndpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServer {
    Logger log = LoggerFactory.getLogger(AuthorizationServer.class);

    private ArrayList<Endpoint> endpoints;
    ServerServices serverServices;

    public AuthorizationServer(ProvidedServices providedServices) {
        serverServices = new ServerServices(providedServices);

        endpoints = new ArrayList<>();

        endpoints.add(new AuthorizationEndpoint(serverServices));
        endpoints.add(new LoginEndpoint(serverServices));
        endpoints.add(new TokenEndpoint(serverServices));
    }

    public Exchange invokeOn(Exchange exc) throws Exception {
        log.info("Authorization server connect");
        for (Endpoint endpoint : endpoints)
            if (exc.getResponse() == null)
                endpoint.useIfResponsible(exc);
        return exc;
    }

}
