package com.bornium.security.oauth2openid.token;

import org.jose4j.lang.JoseException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class CombinedTokenManager {

    private final BearerTokenProvider tokenProvider;
    private final IdTokenProvider idTokenProvider;

    TokenManager authorizationCodes;
    TokenManager accessTokens;
    TokenManager refreshTokens;
    TokenManager idTokens;


    public CombinedTokenManager() throws JoseException {
        this(new IdTokenProvider());
    }

    public CombinedTokenManager(IdTokenProvider idTokenProvider) {
        this.idTokenProvider = idTokenProvider;
        tokenProvider = new BearerTokenProvider();

        authorizationCodes = new TokenManager();
        accessTokens = new TokenManager();
        refreshTokens = new TokenManager();
        idTokens = new TokenManager();
    }

    public String getJwk() {
        return idTokenProvider.getJwk();
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

    public Token findToken(String value) {
        if (getRefreshTokens().tokenExists(value))
            return getRefreshTokens().getToken(value);
        if (getAccessTokens().tokenExists(value))
            return getAccessTokens().getToken(value);
        return null;
        // we wont search for other tokens as finding tokens is only needed with revocation endpoint
    }

    public Token addTokenToManager(TokenManager manager, Token token) {
        synchronized(manager) {
            manager.addToken(token);
        }
        return token;
    }

    public Token createToken(String value, String username, String clientId, Duration validFor, String claims, String scope, String redirectUri) {
        return new Token(value, username, clientId, LocalDateTime.now(), validFor, claims, scope, redirectUri);
    }

    public Token createBearerToken(String username, String clientId, Duration validFor, String claims, String scope, String redirectUri) {
        return createToken(tokenProvider.get(), username, clientId, validFor, claims, scope,redirectUri);
    }

    public Token createChildToken(String value, Duration validFor, Token parent) {
        Token result = createToken(value, parent.getUsername(), parent.getClientId(), validFor, parent.getClaims(), parent.getScope(),parent.getRedirectUri());
        parent.addChild(result);
        return result;
    }

    public Token createChildBearerToken(Duration validFor, Token parent) {
        return createChildToken(tokenProvider.get(), validFor, parent);
    }

    public Token createBearerTokenWithDefaultDuration(String username, String clientId, String claims, String scope, String redirectUri) {
        return createBearerToken(username, clientId, Token.getDefaultValidFor(), claims, scope,redirectUri);
    }

    public Token createChildBearerTokenWithDefaultDuration(Token parent) {
        return createChildBearerToken(Token.defaultValidFor, parent);
    }

    public Token createIdToken(String issuer, String subject, String clientId, Duration validFor, String authTime, String nonce, Map<String, Object> claims, String username, String scope, String redirectUri) throws JoseException {
        String idToken = idTokenProvider.createIdToken(issuer, subject, clientId, validFor, authTime, nonce, claims);
        String claimsString = compactMapClaimsToStringClaims(claims);
        return createToken(idToken, username, clientId, validFor, claimsString, scope,redirectUri);
    }

    public Token createChildIdToken(String issuer, String subject, String clientId, Duration validFor, String authTime, String nonce, Map<String, Object> claims, Token parent) throws JoseException {
        Token result = createIdToken(issuer, subject, clientId, validFor, authTime, nonce, claims, parent.getUsername(), parent.getScope(),parent.getRedirectUri());
        parent.addChild(result);
        return result;
    }

    private String compactMapClaimsToStringClaims(Map<String, Object> claims) {
        StringBuilder builder = new StringBuilder();
        for (String claim : claims.keySet())
            builder.append(claim).append(" ");

        return builder.toString().trim();
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

    public BearerTokenProvider getTokenProvider() {
        return tokenProvider;
    }

    public IdTokenProvider getIdTokenProvider() {
        return idTokenProvider;
    }
}
