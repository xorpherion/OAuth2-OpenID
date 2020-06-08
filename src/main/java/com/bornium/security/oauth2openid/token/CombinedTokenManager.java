package com.bornium.security.oauth2openid.token;

import com.bornium.security.oauth2openid.providers.TimingProvider;
import com.bornium.security.oauth2openid.providers.TokenPersistenceProvider;
import com.bornium.security.oauth2openid.server.TimingContext;
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
    private final TokenPersistenceProvider tokenPersistenceProvider;
    private final UserTokenProvider userTokenProvider;
    private final TimingProvider timingProvider;

    TokenManager authorizationCodes;
    TokenManager accessTokens;
    TokenManager refreshTokens;
    TokenManager idTokens;
    TokenManager deviceCodes;
    TokenManager userCodes;

    public CombinedTokenManager(IdTokenProvider idTokenProvider, TokenPersistenceProvider tokenPersistenceProvider, TimingProvider timingProvider) {
        this.idTokenProvider = idTokenProvider;
        tokenProvider = new BearerTokenProvider();
        this.tokenPersistenceProvider = tokenPersistenceProvider;
        userTokenProvider = new UserTokenProvider();
        this.timingProvider = timingProvider;

        authorizationCodes = tokenPersistenceProvider.createTokenManager("auth");
        accessTokens = tokenPersistenceProvider.createTokenManager("access");
        refreshTokens = tokenPersistenceProvider.createTokenManager("refresh");
        idTokens = tokenPersistenceProvider.createTokenManager("id");
        deviceCodes = tokenPersistenceProvider.createTokenManager("device");
        userCodes = tokenPersistenceProvider.createTokenManager("user");
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

    public Token createToken(String value, String username, String clientId, Duration validFor, String claims, String scope, String redirectUri, String nonce) {
        return tokenPersistenceProvider.createToken(value, username, clientId, LocalDateTime.now(), validFor, claims, scope, redirectUri, nonce);
    }

    public Token createBearerToken(String username, String clientId, Duration validFor, String claims, String scope, String redirectUri, String nonce) {
        return createToken(tokenProvider.get(), username, clientId, validFor, claims, scope,redirectUri, nonce);
    }

    public Token createDeviceToken(String username, String clientId, Duration validFor, String claims, String scope, String redirectUri, String nonce) {
        return createToken("pre:" + tokenProvider.get(), username, clientId, validFor, claims, scope, redirectUri, nonce);
    }

    public Token createChildToken(String value, Duration validFor, Token parent) {
        Token result = createToken(value, parent.getUsername(), parent.getClientId(), validFor, parent.getClaims(), parent.getScope(), parent.getRedirectUri(), parent.getNonce());
        parent.addChild(result);
        return result;
    }

    public Token createChildBearerToken(Duration validFor, Token parent) {
        return createChildToken(tokenProvider.get(), validFor, parent);
    }

    public Token createBearerTokenWithDefaultDuration(String username, String clientId, String claims, String scope, String redirectUri, String nonce) {
        Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(clientId));
        return createBearerToken(username, clientId, validFor, claims, scope, redirectUri, nonce);
    }

    public Token createDeviceTokenWithDefaultDuration(String clientId, String scope) {
        Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(clientId));
        return createDeviceToken(userTokenProvider.get(), clientId, validFor, null, scope, null, null);
    }

    public Token createDeviceTokenWithDefaultDuration(String deviceCode, String username, String clientId, String scope) {
        Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(clientId));
        return createToken(deviceCode, username, clientId, validFor, null, scope, null, null);
    }

    public Token createUserToken(String userCode, String deviceCode, String clientId, String scope) {
        Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(clientId));
        return createToken(userCode, deviceCode, null, validFor, null, scope, null, null);
    }

    public Token createChildBearerTokenWithDefaultDuration(Token parent) {
        Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(parent.getClientId()));
        return createChildBearerToken(validFor, parent);
    }

    public Token createIdToken(String issuer, String subject, String clientId, Duration validFor, String authTime, String nonce, Map<String, Object> claims, String username, String scope, String redirectUri) throws JoseException {
        String idToken = idTokenProvider.createIdToken(issuer, subject, clientId, validFor, authTime, nonce, claims);
        String claimsString = compactMapClaimsToStringClaims(claims);
        return createToken(idToken, username, clientId, validFor, claimsString, scope, redirectUri, nonce);
    }

    public Token createChildIdToken(String issuer, String subject, String clientId, Duration validFor, String authTime, String nonce, Map<String, Object> claims, Token parent) throws JoseException {
        Token result = createIdToken(issuer, subject, clientId, validFor, authTime, nonce, claims, parent.getUsername(), parent.getScope(), parent.getRedirectUri());
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

    public TokenManager getDeviceCodes() {
        return deviceCodes;
    }

    public TokenManager getUserCodes() {
        return userCodes;
    }

    public BearerTokenProvider getTokenProvider() {
        return tokenProvider;
    }

    public IdTokenProvider getIdTokenProvider() {
        return idTokenProvider;
    }
}
