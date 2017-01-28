package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.token.AuthorizationEndpointTokenManager;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class AuthorizationEndpointFlowDecider extends FlowDecider {

    public AuthorizationEndpointFlowDecider(AuthorizationEndpointTokenManager tokenManager, ServerProvider serverProvider, Exchange exc) {
        super(serverProvider, exc, getFlows(tokenManager, serverProvider, exc));
    }

    private static Flow[] getFlows(AuthorizationEndpointTokenManager tokenManager, ServerProvider serverProvider, Exchange exc) {
        ArrayList<Flow> flows = new ArrayList<>();

        flows.add(new CodeFlow(serverProvider,tokenManager, exc));
        flows.add(new TokenFlow(serverProvider,tokenManager, exc));
        flows.add(new IdTokenFlow(serverProvider,tokenManager, exc));

        return flows.toArray(new Flow[0]);
    }
}
