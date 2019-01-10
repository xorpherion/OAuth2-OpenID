package com.bornium.security.oauth2openid.server;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.server.endpoints.*;
import com.bornium.security.oauth2openid.token.IdTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServer {
    Logger log = LoggerFactory.getLogger(AuthorizationServer.class);

    private ArrayList<Endpoint> endpoints;
    ServerServices serverServices;

    public AuthorizationServer(ProvidedServices providedServices) throws Exception {
        this(providedServices, new IdTokenProvider());
    }

    public AuthorizationServer(ProvidedServices providedServices, IdTokenProvider idTokenProvider) throws Exception {
        this(providedServices, idTokenProvider, serverServices -> Arrays.asList(new LoginEndpoint(serverServices)));
    }

    public AuthorizationServer(ProvidedServices providedServices, IdTokenProvider idTokenProvider, EndpointFactory loginEndpointFactory) throws Exception {
        serverServices = new ServerServices(providedServices, idTokenProvider);

        endpoints = new ArrayList<>();

        endpoints.add(new AuthorizationEndpoint(serverServices));
        endpoints.add(new TokenEndpoint(serverServices));
        endpoints.add(new UserinfoEndpoint(serverServices));
        endpoints.add(new RevocationEndpoint(serverServices));
        endpoints.add(new JwkEndpoint(serverServices));
        endpoints.add(new WellKnownEndpoint(serverServices));

        endpoints.addAll(loginEndpointFactory.createEndpoints(serverServices));
    }

    public Exchange invokeOn(Exchange exc) throws Exception {
        //log.info("Authorization server connect");
        for (Endpoint endpoint : endpoints)
            if (exc.getResponse() == null)
                endpoint.useIfResponsible(exc);
        if (exc.getResponse() == null)
            exc.setResponse(new ResponseBuilder().statuscode(404).body("Not found - try /userinfo with access token in Authorization Header").build());
        addMissingHeaders(exc);
        return exc;
    }

    private void addMissingHeaders(Exchange exc) {
        if (exc != null && exc.getResponse() != null) {
            exc.getResponse().getHeader().append(Constants.HEADER_CACHE_CONTROL, Constants.HEADER_VALUE_NO_STORE);
            exc.getResponse().getHeader().append(Constants.HEADER_PRAGMA, Constants.HEADER_VALUE_NO_CACHE);
            exc.getResponse().getHeader().append(Constants.HEADER_X_FRAME_OPTIONS, Constants.HEADER_VALUE_SAMEORIGIN);
            if(exc.getResponse().getStatuscode() == 401)
                exc.getResponse().getHeader().add("WWW-Authenticate","Bearer realm=\"OAuth2\"");
        }
    }

    public ServerServices getServerServices() {
        return serverServices;
    }
}
