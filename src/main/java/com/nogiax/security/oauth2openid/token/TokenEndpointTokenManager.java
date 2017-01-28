package com.nogiax.security.oauth2openid.token;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class TokenEndpointTokenManager extends AuthorizationEndpointTokenManager {

    BearerTokenManager refreshTokens;

    public TokenEndpointTokenManager(){
        super();
        refreshTokens = new BearerTokenManager();
    }
}
