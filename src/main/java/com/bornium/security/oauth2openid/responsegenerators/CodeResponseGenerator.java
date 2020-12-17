package com.bornium.security.oauth2openid.responsegenerators;

import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CodeResponseGenerator extends ResponseGenerator {

    public CodeResponseGenerator(AuthorizationServer serverServices, GrantContext ctx) {
        super(serverServices, ctx, Constants.TOKEN_TYPE_CODE);
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
        String username = getCtx().getValue(Constants.LOGIN_USERNAME);
        String clientId = getCtx().getValue(Constants.PARAMETER_CLIENT_ID);
        String claims = getCtx().getValue(Constants.PARAMETER_CLAIMS);
        String scope = getCtx().getValue(Constants.PARAMETER_SCOPE);
        String state = getCtx().getValue(Constants.PARAMETER_STATE);
        String redirectUri = getCtx().getValue(Constants.PARAMETER_REDIRECT_URI);
        String nonce = getCtx().getValue(Constants.PARAMETER_NONCE);
        Token authCode = getTokenManager().addTokenToManager(getTokenManager().getAuthorizationCodes(), getTokenManager().createBearerTokenWithDefaultDuration(username, clientId, claims, scope, redirectUri, nonce));

        Map<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_CODE, authCode.getValue());
        result.put(Constants.PARAMETER_STATE, state);

        getCtx().putValue(Constants.SESSION_AUTHORIZATION_CODE, authCode.getValue());

        return result;
    }
}
