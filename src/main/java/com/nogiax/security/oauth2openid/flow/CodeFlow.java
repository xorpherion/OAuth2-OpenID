package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.token.AuthorizationEndpointTokenManager;
import com.nogiax.security.oauth2openid.token.Token;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CodeFlow extends Flow {

    private final AuthorizationEndpointTokenManager tokenManager;

    public CodeFlow(ServerProvider serverProvider, AuthorizationEndpointTokenManager tokenManager, Exchange exc) {
        super(Constants.GRANT_CODE, serverProvider, exc);
        this.tokenManager = tokenManager;
    }

    @Override
    public Map<String, String> invokeFlow() throws Exception {
        String username = getSession().getValue(Constants.LOGIN_USERNAME);
        String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
        String claims = getSession().getValue(Constants.PARAMETER_CLAIMS);
        String state = getSession().getValue(Constants.PARAMETER_STATE);
        Token authCode = tokenManager.createAuthorizationCodeWithDefaultDuration(username, clientId, claims);

        Map<String,String> result = new HashMap<>();
        result.put(Constants.PARAMETER_AUTHORIZATION_CODE, authCode.getValue());
        result.put(Constants.PARAMETER_STATE,state);

        return result;
    }
}
