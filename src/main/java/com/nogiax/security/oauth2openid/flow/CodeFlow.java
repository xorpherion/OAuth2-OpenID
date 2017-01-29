package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CodeFlow extends Flow {

    public CodeFlow(ServerServices serverServices, Exchange exc) {
        super(Constants.GRANT_CODE, serverServices, exc);
    }

    @Override
    public Map<String, String> invokeFlow() throws Exception {
        String username = getSession().getValue(Constants.LOGIN_USERNAME);
        String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
        String claims = getSession().getValue(Constants.PARAMETER_CLAIMS);
        String state = getSession().getValue(Constants.PARAMETER_STATE);
        Token authCode = getServerServices().getTokenManager().createAuthorizationCodeWithDefaultDuration(username, clientId, claims);

        Map<String,String> result = new HashMap<>();
        result.put(Constants.PARAMETER_AUTHORIZATION_CODE, authCode.getValue());
        result.put(Constants.PARAMETER_STATE,state);

        return result;
    }
}
