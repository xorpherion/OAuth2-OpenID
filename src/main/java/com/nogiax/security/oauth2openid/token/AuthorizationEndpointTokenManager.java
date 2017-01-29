package com.nogiax.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationEndpointTokenManager {

    private final BearerTokenProvider tokenProvider;

    BearerTokenManager authorizationCodes;
    BearerTokenManager accessTokens;
    JWTTokenManager idTokens;

    public AuthorizationEndpointTokenManager(){
        tokenProvider = new BearerTokenProvider();

        authorizationCodes = new BearerTokenManager();
        accessTokens = new BearerTokenManager();
        idTokens = new JWTTokenManager();
    }

    public Token createAuthorizationCode(String user, String clientId, Duration validFor, String claims){
        Token authorizationCode = new Token(tokenProvider.get(),user,clientId, LocalDateTime.now(), validFor,claims);
        authorizationCodes.addToken(authorizationCode);
        return authorizationCode;
    }

    public Token createAuthorizationCodeWithDefaultDuration(String user, String clientId, String claims){
        return createAuthorizationCode(user, clientId, Token.getDefaultValidFor(),claims);
    }




}
