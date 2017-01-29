package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ServerServices;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class AuthorizationEndpointFlowDecider extends FlowDecider {

    public AuthorizationEndpointFlowDecider(ServerServices serverServices, Exchange exc) {
        super(serverServices, exc, getFlows(serverServices, exc));
    }

    private static Flow[] getFlows(ServerServices serverServices, Exchange exc) {
        ArrayList<Flow> flows = new ArrayList<>();

        flows.add(new CodeFlow(serverServices, exc));
        flows.add(new TokenFlow(serverServices, exc));
        flows.add(new IdTokenFlow(serverServices, exc));

        return flows.toArray(new Flow[0]);
    }
}
