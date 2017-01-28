package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.Session;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public abstract class Flow {

    private final String flow;
    private final ServerProvider serverProvider;
    private final Exchange exc;

    public Flow(String flow, ServerProvider serverProvider, Exchange exc) {
        this.flow = flow;
        this.serverProvider = serverProvider;
        this.exc = exc;
    }

    public boolean isMyFlow() throws Exception {
        Session session = getSession();
        String askedFlow = session.getValue(Constants.PARAMETER_RESPONSE_TYPE);
        if (askedFlow != null) {
            String[] askedFlows = askedFlow.split(Pattern.quote("_"));
            for (String f : askedFlows)
                if (f.equals(flow))
                    return true;
        }
        return false;
    }

    private Session getSession() {
        return serverProvider.getSessionProvider().getSession(exc);
    }

    public abstract Map<String, String> invokeFlow();
}
