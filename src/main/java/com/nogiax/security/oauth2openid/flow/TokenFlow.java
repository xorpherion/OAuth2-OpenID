package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.token.AuthorizationEndpointTokenManager;

import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class TokenFlow extends Flow {
    public TokenFlow(ServerProvider serverProvider, AuthorizationEndpointTokenManager tokenManager, Exchange exc) {
        super(Constants.GRANT_TOKEN, serverProvider, exc);
    }

    @Override
    public Map<String, String> invokeFlow() {
        return null;
    }
}
