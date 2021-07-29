package com.bornium.security.oauth2openid.responsegenerators;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.token.CombinedTokenManager;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public abstract class ResponseGenerator {

    private final String[] responseTypes;
    private final AuthorizationServer serverServices;
    private final GrantContext ctx;

    public ResponseGenerator(AuthorizationServer serverServices, GrantContext ctx, String... responseTypes) {
        this.responseTypes = responseTypes;
        this.serverServices = serverServices;
        this.ctx = ctx;
    }

    public boolean isMyResponseType(String askedResponseType) throws Exception {
        if (askedResponseType != null) {
            String[] askedFlows = askedResponseType.split(Pattern.quote(" "));
            for (String f : askedFlows)
                for (String r : responseTypes)
                    if (f.equals(r))
                        return true;
        }
        return false;
    }

    protected Map<String, String> errorParams(String error) {
        Map<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_ERROR, error);
        return result;
    }

    public abstract Map<String, String> invokeResponse() throws Exception;

    protected Map<String, String> invalidScopeError() {
        return errorParams(Constants.ERROR_INVALID_SCOPE);
    }

    protected CombinedTokenManager getTokenManager() {
        return getServerServices().getTokenManager();
    }

    protected GrantContext getCtx() {
        return ctx;
    }

    public String[] getResponseType() {
        return responseTypes;
    }

    public AuthorizationServer getServerServices() {
        return serverServices;
    }
}
