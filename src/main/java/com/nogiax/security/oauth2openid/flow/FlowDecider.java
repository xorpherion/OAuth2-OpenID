package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.ServerServices;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class FlowDecider {

    protected final Exchange exc;
    protected final ServerServices serverServices;

    protected ArrayList<Flow> flows;

    public FlowDecider(ServerServices serverServices, Exchange exc, Flow... flows) {
        this.serverServices = serverServices;
        this.exc = exc;

        this.flows = new ArrayList<>();
        for (Flow flow : flows)
            this.flows.add(flow);
    }

    public Map<String, String> invokeFlows() throws Exception {
        HashMap<String, String> result = new HashMap<>();
        for (Flow flow : flows)
            if (flow.isMyFlow())
                result.putAll(flow.invokeFlow());
        return result;
    }
}
