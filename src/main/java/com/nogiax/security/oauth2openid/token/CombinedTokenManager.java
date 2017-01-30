package com.nogiax.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class CombinedTokenManager {

    private final BearerTokenProvider tokenProvider;
    private final JwtTokenProvider jwtProvider;

    TokenManager authorizationCodes;
    TokenManager accessTokens;
    TokenManager refreshTokens;
    TokenManager idTokens;


    public CombinedTokenManager(){
        tokenProvider = new BearerTokenProvider();
        jwtProvider = new JwtTokenProvider();

        authorizationCodes = new TokenManager();
        accessTokens = new TokenManager();
        refreshTokens = new TokenManager();
        idTokens = new TokenManager();
    }

//    public Token createAuthorizationCode(String user, String clientId, Duration validFor, String claims){
//        return addTokenToManager(authorizationCodes,createBearerToken(user,clientId,validFor,claims));
//    }
//
//    public Token createAuthorizationCodeWithDefaultDuration(String user, String clientId, String claims){
//        return createAuthorizationCode(user, clientId, Token.getDefaultValidFor(),claims);
//    }
//
//    public Token createAccessToken(String user, String clientId, Duration validFor, String claims){
//        return addTokenToManager(accessTokens,createBearerToken(user,clientId,validFor,claims));
//    }
//
//    public Token createAccessTokenWithDefaultDuration(String user, String clientId, String claims){
//        return createAccessToken(user,clientId,Token.getDefaultValidFor(),claims);
//    }
//
//
//    public Token createRefeshToken(String user, String clientId, Duration validFor, String claims){
//        return addTokenToManager(refreshTokens,createBearerToken(user,clientId,validFor,claims));
//    }
//
//    public Token createRefeshTokenWithDefaultDuration(String user, String clientId, String claims){
//        return createAccessToken(user,clientId,Token.getDefaultValidFor(),claims);
//    }

    public Token addTokenToManager(TokenManager manager, Token token){
        manager.addToken(token);
        return token;
    }

    public Token createToken(String value, String username, String clientId, Duration validFor, String claims, String scope){
        return new Token(value,username,clientId,LocalDateTime.now(),validFor,claims, scope);
    }

    public Token createBearerToken(String username, String clientId, Duration validFor, String claims, String scope){
        return createToken(tokenProvider.get(),username,clientId,validFor,claims, scope);
    }

    public Token createChildToken(String value, Duration validFor, Token parent){
        Token result = createToken(value,parent.getUsername(),parent.getClientId(),validFor,parent.getClaims(), parent.getScope());
        parent.addChild(result);
        return result;
    }

    public Token createChildBearerToken(Duration validFor, Token parent){
        return createChildToken(tokenProvider.get(),validFor,parent);
    }

    public Token createBearerTokenWithDefaultDuration(String username, String clientId,String claims, String scope){
        return createBearerToken(username,clientId,Token.getDefaultValidFor(),claims,scope);
    }

    public Token createChildBearerTokenWithDefaultDuration(Token parent){
        return createChildBearerToken(Token.defaultValidFor,parent);
    }




    public TokenManager getAuthorizationCodes() {
        return authorizationCodes;
    }

    public TokenManager getAccessTokens() {
        return accessTokens;
    }

    public TokenManager getRefreshTokens() {
        return refreshTokens;
    }

    public TokenManager getIdTokens() {
        return idTokens;
    }
}
