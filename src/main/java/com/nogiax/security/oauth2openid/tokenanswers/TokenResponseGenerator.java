package com.nogiax.security.oauth2openid.tokenanswers;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class TokenResponseGenerator extends ResponseGenerator {
    public TokenResponseGenerator(ServerServices serverServices, Exchange exc) {
        super(Constants.TOKEN_TYPE_TOKEN, serverServices, exc);
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
        String code = getSession().getValue(Constants.SESSION_AUTHORIZATION_CODE);
        String responseType = getSession().getValue(Constants.PARAMETER_RESPONSE_TYPE);

        Token authorizationCode = getTokenManager().getAuthorizationCodes().getToken(code);

        Token accessToken = getTokenManager().addTokenToManager(getTokenManager().getAccessTokens(), getTokenManager().createChildBearerTokenWithDefaultDuration(authorizationCode));
        Token refreshToken = getTokenManager().addTokenToManager(getTokenManager().getRefreshTokens(), getTokenManager().createChildBearerToken(Token.getDefaultValidForLong(), authorizationCode));

        Map<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_ACCESS_TOKEN, accessToken.getValue());
        result.put(Constants.PARAMETER_TOKEN_TYPE, Constants.PARAMETER_VALUE_BEARER);
        result.put(Constants.PARAMETER_EXPIRES_IN, String.valueOf(accessToken.getValidFor().getSeconds()));
        if (!responseType.equals(Constants.PARAMETER_VALUE_TOKEN) || !responseType.equals(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS))
            result.put(Constants.PARAMETER_REFRESH_TOKEN, refreshToken.getValue());

        return result;
    }


}
