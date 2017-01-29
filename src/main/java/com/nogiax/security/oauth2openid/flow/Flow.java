package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public abstract class Flow {

    private final String flow;
    private final ServerServices serverServices;
    private final Exchange exc;

    public Flow(String flow, ServerServices serverServices, Exchange exc) {
        this.flow = flow;
        this.serverServices = serverServices;
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

    protected Session getSession() {
        return serverServices.getProvidedServices().getSessionProvider().getSession(exc);
    }

    public abstract Map<String, String> invokeFlow() throws Exception;

    public String getFlow() {
        return flow;
    }

    public ServerServices getServerServices() {
        return serverServices;
    }

    public Exchange getExc() {
        return exc;
    }
}
