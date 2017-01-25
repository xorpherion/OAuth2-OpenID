package com.nogiax.security.oauth2openid.server;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.endpoints.AuthorizationEndpoint;
import com.nogiax.security.oauth2openid.endpoints.Endpoint;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServer {

    private ArrayList<Endpoint> endpoints;

    public AuthorizationServer(ServerProvider serverProvider){
        endpoints = new ArrayList<>();

        endpoints.add(new AuthorizationEndpoint(serverProvider));
    }

    public Exchange invokeOn(Exchange exc) {
        for(Endpoint endpoint : endpoints)
            if(exc.getResponse() == null)
                endpoint.useIfResponsible(exc);
        return exc;
    }

}
