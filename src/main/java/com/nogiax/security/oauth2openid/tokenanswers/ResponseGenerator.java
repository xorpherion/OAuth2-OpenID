package com.nogiax.security.oauth2openid.tokenanswers;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.token.CombinedTokenManager;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public abstract class ResponseGenerator {

    private final String responseType;
    private final ServerServices serverServices;
    private final Exchange exc;

    public ResponseGenerator(String responseType, ServerServices serverServices, Exchange exc) {
        this.responseType = responseType;
        this.serverServices = serverServices;
        this.exc = exc;
    }

    public boolean isMyResponseType(String askedResponseType) throws Exception {
        if (askedResponseType != null) {
            String[] askedFlows = askedResponseType.split(Pattern.quote("_"));
            for (String f : askedFlows)
                if (f.equals(responseType))
                    return true;
        }
        return false;
    }

    protected Map<String,String> errorParams(String error){
        Map<String,String> result = new HashMap<>();
        result.put(Constants.PARAMETER_ERROR, error);
        return result;
    }

    protected Map<String,String> invalidScopeError() {
        return errorParams(Constants.ERROR_INVALID_SCOPE);
    }

    protected CombinedTokenManager getTokenManager() {
        return getServerServices().getTokenManager();
    }

    protected Session getSession() {
        return serverServices.getProvidedServices().getSessionProvider().getSession(exc);
    }

    public abstract Map<String, String> invokeResponse() throws Exception;

    public String getResponseType() {
        return responseType;
    }

    public ServerServices getServerServices() {
        return serverServices;
    }

    public Exchange getExc() {
        return exc;
    }
}
