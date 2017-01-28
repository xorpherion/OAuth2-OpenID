package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ServerProvider;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class AuthorizationEndpointFlowDecider extends FlowDecider {
    public AuthorizationEndpointFlowDecider(ServerProvider serverProvider, Exchange exc) {
        super(serverProvider, exc, getFlows(serverProvider, exc));
    }

    private static Flow[] getFlows(ServerProvider serverProvider, Exchange exc) {
        ArrayList<Flow> flows = new ArrayList<>();

        flows.add(new CodeFlow(serverProvider, exc));
        flows.add(new TokenFlow(serverProvider, exc));
        flows.add(new IdTokenFlow(serverProvider, exc));

        return flows.toArray(new Flow[0]);
    }
}
