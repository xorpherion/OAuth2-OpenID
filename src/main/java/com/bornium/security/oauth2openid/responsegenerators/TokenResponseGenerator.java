package com.bornium.security.oauth2openid.responsegenerators;

import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.permissions.ClaimsParameter;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.providers.TimingProvider;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.TimingContext;
import com.bornium.security.oauth2openid.token.Token;

import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class TokenResponseGenerator extends ResponseGenerator {
    private TimingProvider timingProvider;

    public TokenResponseGenerator(AuthorizationServer serverServices, GrantContext ctx) {
        super(serverServices, ctx, Constants.TOKEN_TYPE_TOKEN, Constants.TOKEN_TYPE_ID_TOKEN);
        timingProvider = serverServices.getProvidedServices().getTimingProvider();
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
        String username = getCtx().getValue(Constants.LOGIN_USERNAME);
        String clientId = getCtx().getValue(Constants.PARAMETER_CLIENT_ID);
        String scope = getCtx().getValue(Constants.PARAMETER_SCOPE);
        String claims = getCtx().getValue(Constants.PARAMETER_CLAIMS);
        String code = getCtx().getValue(Constants.SESSION_AUTHORIZATION_CODE);
        String grantType = getCtx().getValue(Constants.PARAMETER_GRANT_TYPE);
        String refreshTokenValue = getCtx().getValue(Constants.PARAMETER_REFRESH_TOKEN);
        String state = getCtx().getValue(Constants.PARAMETER_STATE);
        String redirectUri = getCtx().getValue(Constants.PARAMETER_REDIRECT_URI);
        String nonce = getCtx().getValue(Constants.PARAMETER_NONCE);
        Set<String> responseTypes = new HashSet<String>(Arrays.asList(getCtx().getValue(Constants.PARAMETER_RESPONSE_TYPE).split(Pattern.quote(" "))));

        Token parentToken = getOrCreateParentToken(username, clientId, scope, claims, code, refreshTokenValue, redirectUri, nonce);
        if(username == null && parentToken.getUsername() != null)
            username = parentToken.getUsername();
        if(claims == null && parentToken.getClaims() != null)
            claims = parentToken.getClaims();

        Map<String, String> result = new HashMap<>();

        String accessTokenValue = createAccessTokenIfNeeded(grantType, responseTypes, parentToken, result);

        createIdTokenIfNeeded(username, clientId, scope, claims, code, responseTypes, parentToken, result, accessTokenValue);

        result.put(Constants.PARAMETER_STATE, state);
        parentToken.incrementUsage();

        return result;
    }

    private void createIdTokenIfNeeded(String username, String clientId, String scope, String claims, String code, Set<String> responseTypes, Token parentToken, Map<String, String> result, String accessTokenValue) throws Exception {
        if (responseTypes.contains(Constants.PARAMETER_VALUE_ID_TOKEN) && isOpenIdScope()) {
            String authTime = getCtx().getValue(Constants.PARAMETER_AUTH_TIME);
            String nonce = parentToken.getNonce();
            Set<String> idTokenClaimNames = new ClaimsParameter(claims).getAllIdTokenClaimNames();
            idTokenClaimNames.addAll(getServerServices().getSupportedScopes().getClaimsForScope(scope));
            idTokenClaimNames = getServerServices().getSupportedClaims().getValidClaims(idTokenClaimNames);
            Map<String, Object> idTokenClaims = getServerServices().getProvidedServices().getUserDataProvider().getClaims(username, idTokenClaimNames);

            idTokenClaims.put(Constants.CLAIM_AT_HASH, Util.halfHashFromValue(Constants.ALG_SHA_256, accessTokenValue));
            idTokenClaims.put(Constants.CLAIM_C_HASH, Util.halfHashFromValue(Constants.ALG_SHA_256, code));
            idTokenClaims.put(Constants.PARAMETER_NONCE, nonce);
            idTokenClaims.put(Constants.PARAMETER_AUTH_TIME, authTime);

            Duration validFor = timingProvider.getShortTokenValidFor(new TimingContext(clientId));
            Token idToken = getTokenManager().addTokenToManager(getTokenManager().getIdTokens(),getServerServices().getTokenManager().createChildIdToken(getIssuer(), getSubClaim(username), clientId, validFor, authTime, nonce, idTokenClaims, parentToken));

            result.put(Constants.PARAMETER_ID_TOKEN, idToken.getValue());
        }
    }

    private String createAccessTokenIfNeeded(String grantType, Set<String> responseTypes, Token parentToken, Map<String, String> result) {
        String accessTokenValue = null;
        if (responseTypes.contains(Constants.PARAMETER_VALUE_TOKEN)) {
            Token accessToken = getTokenManager().addTokenToManager(getTokenManager().getAccessTokens(), getTokenManager().createChildBearerTokenWithDefaultDuration(parentToken));
            Duration validForLong = timingProvider.getRefreshTokenValidFor(new TimingContext(parentToken.getClientId()));
            Token refreshToken = getTokenManager().addTokenToManager(getTokenManager().getRefreshTokens(), getTokenManager().createChildBearerToken(validForLong, parentToken));

            result.put(Constants.PARAMETER_ACCESS_TOKEN, accessToken.getValue());
            result.put(Constants.PARAMETER_TOKEN_TYPE, Constants.PARAMETER_VALUE_BEARER);
            result.put(Constants.PARAMETER_EXPIRES_IN, String.valueOf(accessToken.getValidFor().getSeconds()));
            if (grantType != null && !(grantType.equals(Constants.PARAMETER_VALUE_TOKEN) || grantType.equals(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS)))
                result.put(Constants.PARAMETER_REFRESH_TOKEN, refreshToken.getValue());

            accessTokenValue = accessToken.getValue();
        }
        return accessTokenValue;
    }

    private Token getOrCreateParentToken(String username, String clientId, String scope, String claims, String code, String refreshTokenValue, String redirectUri, String nonce) throws Exception {
        Token parentToken = null;
        if (refreshTokenValue != null) {
            parentToken = getTokenManager().getRefreshTokens().getToken(refreshTokenValue);
            getCtx().removeValue(Constants.PARAMETER_REFRESH_TOKEN);
        } else if (invokingEndpointIsAuthorizationEndpoint() || code == null) {
            Token fakeAuthToken = getTokenManager().createBearerTokenWithDefaultDuration(username, clientId, claims, scope, redirectUri, nonce);
            getTokenManager().getAuthorizationCodes().addToken(fakeAuthToken);
            parentToken = getTokenManager().getAuthorizationCodes().getToken(fakeAuthToken.getValue());
        } else {
            parentToken = getTokenManager().getAuthorizationCodes().getToken(code);
            getCtx().removeValue(Constants.SESSION_AUTHORIZATION_CODE);
        }
        return parentToken;
    }

    private boolean invokingEndpointIsAuthorizationEndpoint() throws Exception {
        return getCtx().getValue(Constants.SESSION_ENDPOINT).equals(Constants.ENDPOINT_AUTHORIZATION);
    }

    private String getSubClaim(String username) {
        return getServerServices().getProvidedServices().getUserDataProvider().getSubClaim(username);
    }

    private String getIssuer() {
        return getServerServices().getProvidedServices().getIssuer();
    }

    private boolean isOpenIdScope() throws Exception {
        GrantContext ctx = getCtx();
        String scope = ctx.getValue(Constants.PARAMETER_SCOPE);
        if (scope != null && scope.contains(Constants.SCOPE_OPENID))
            return true;
        return false;
    }

}
