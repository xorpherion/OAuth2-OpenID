package com.bornium.security.oauth2openid.responsegenerators;

import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.server.AuthorizationServer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CombinedResponseGenerator {

    protected final GrantContext ctx;
    protected final AuthorizationServer serverServices;

    protected ArrayList<ResponseGenerator> responseGenerators;

    public CombinedResponseGenerator(AuthorizationServer serverServices, GrantContext ctx) {
        this.serverServices = serverServices;
        this.ctx = ctx;

        this.responseGenerators = new ArrayList<>();
        responseGenerators.add(new CodeResponseGenerator(serverServices, ctx));
        responseGenerators.add(new TokenResponseGenerator(serverServices, ctx));
    }

    public Map<String, String> invokeResponse(String responseType) throws Exception {
        HashMap<String, String> result = new HashMap<>();
        for (ResponseGenerator responseGenerator : responseGenerators)
            if (responseGenerator.isMyResponseType(responseType))
                result.putAll(responseGenerator.invokeResponse());

        for (Map.Entry<String, String> e : result.entrySet())
            ctx.putValue(e.getKey(),e.getValue());

        return result;
    }
}
