package com.nogiax.security.oauth2openid.responsegenerators;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.server.ServerServices;
import com.nogiax.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CodeResponseGenerator extends ResponseGenerator {

    public CodeResponseGenerator(ServerServices serverServices, Exchange exc) {
        super(serverServices, exc, Constants.TOKEN_TYPE_CODE);
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
        String username = getSession().getValue(Constants.LOGIN_USERNAME);
        String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
        String claims = getSession().getValue(Constants.PARAMETER_CLAIMS);
        String scope = getSession().getValue(Constants.PARAMETER_SCOPE);
        String state = getSession().getValue(Constants.PARAMETER_STATE);
        String redirectUri = getSession().getValue(Constants.PARAMETER_REDIRECT_URI);
        Token authCode = getTokenManager().addTokenToManager(getTokenManager().getAuthorizationCodes(), getTokenManager().createBearerTokenWithDefaultDuration(username, clientId, claims, scope,redirectUri));

        Map<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_CODE, authCode.getValue());
        result.put(Constants.PARAMETER_STATE, state);

        getSession().putValue(Constants.SESSION_AUTHORIZATION_CODE, authCode.getValue());

        return result;
    }
}
