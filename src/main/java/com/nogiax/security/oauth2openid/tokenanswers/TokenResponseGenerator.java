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
        String username = getSession().getValue(Constants.LOGIN_USERNAME);
        String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
        String scope = getSession().getValue(Constants.PARAMETER_SCOPE);
        String claims = getSession().getValue(Constants.PARAMETER_CLAIMS);
        String code = getSession().getValue(Constants.SESSION_AUTHORIZATION_CODE);
        String grantType = getSession().getValue(Constants.PARAMETER_GRANT_TYPE);
        String refreshTokenValue = getSession().getValue(Constants.PARAMETER_REFRESH_TOKEN);


        Token parentToken = null;
        if(refreshTokenValue != null){
            parentToken = getTokenManager().getRefreshTokens().getToken(refreshTokenValue);
            getSession().removeValue(Constants.PARAMETER_REFRESH_TOKEN);
        }
        else if (code == null) {
            Token fakeAuthToken = getTokenManager().createBearerTokenWithDefaultDuration(username, clientId, scope, claims);
            getTokenManager().getAuthorizationCodes().addToken(fakeAuthToken);
            code = fakeAuthToken.getValue();
            parentToken = getTokenManager().getAuthorizationCodes().getToken(code);
        }else{
            parentToken = getTokenManager().getAuthorizationCodes().getToken(code);
            getSession().removeValue(Constants.SESSION_AUTHORIZATION_CODE);
        }


        Token accessToken = getTokenManager().addTokenToManager(getTokenManager().getAccessTokens(), getTokenManager().createChildBearerTokenWithDefaultDuration(parentToken));
        Token refreshToken = getTokenManager().addTokenToManager(getTokenManager().getRefreshTokens(), getTokenManager().createChildBearerToken(Token.getDefaultValidForLong(), parentToken));
        parentToken.incrementUsage();


        Map<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_ACCESS_TOKEN, accessToken.getValue());
        result.put(Constants.PARAMETER_TOKEN_TYPE, Constants.PARAMETER_VALUE_BEARER);
        result.put(Constants.PARAMETER_EXPIRES_IN, String.valueOf(accessToken.getValidFor().getSeconds()));
        if (grantType != null && !(grantType.equals(Constants.PARAMETER_VALUE_TOKEN) || grantType.equals(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS)))
            result.put(Constants.PARAMETER_REFRESH_TOKEN, refreshToken.getValue());

        return result;
    }


}
