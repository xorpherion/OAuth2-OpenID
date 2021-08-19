package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.User;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.providers.ConfigProvider;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.responsegenerators.CombinedResponseGenerator;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.TokenContext;
import com.bornium.security.oauth2openid.token.Token;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class TokenEndpoint extends Endpoint {
    private final ConfigProvider configProvider;

    public TokenEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_TOKEN);

        configProvider = serverServices.getProvidedServices().getConfigProvider();
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        //log.info("Token endpoint");

        boolean clientIsAuthorized = false;
        String clientId = null;
        if (exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION) != null) {
            try {
                User clientData = Util.decodeFromBasicAuthValue(exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION));
                clientIsAuthorized = serverServices.getProvidedServices().getClientDataProvider().verify(clientData.getName(), clientData.getPassword());
                if (clientIsAuthorized)
                    clientId = clientData.getName();
            } catch (Exception e) {
                clientIsAuthorized = false;
                clientId = null;
            }
        }
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
        params = Parameters.stripEmptyParams(params);

        GrantContext ctx = serverServices.getProvidedServices().getGrantContextProvider().findByIdOrCreate(params.get(Constants.PARAMETER_CODE));

        if (clientId == null)
            clientId = params.get(Constants.PARAMETER_CLIENT_ID);
        if (clientId == null) {
            log.debug("No clientId detected.");
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        if (!clientIsAuthorized && serverServices.getProvidedServices().getClientDataProvider().isConfidential(clientId) && !serverServices.getProvidedServices().getClientDataProvider().verify(clientId,params.get("client_secret"))) {
            log.debug("Client is confidential and client_secret incorrect.");
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        ctx.putValue(Constants.PARAMETER_CLIENT_ID, clientId);

        if (params.get(Constants.PARAMETER_GRANT_TYPE) == null) {
            log.debug("Parameter 'grant_type' missing.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        String grantType = params.get(Constants.PARAMETER_GRANT_TYPE);
        if (!grantTypeIsSupported(grantType)) {
            log.debug("Unsupported grant_type: " + grantType);
            exc.setResponse(answerWithError(400, Constants.ERROR_UNSUPPORTED_GRANT_TYPE));
            return;
        }
        ctx.putValue(Constants.PARAMETER_GRANT_TYPE, grantType);

        if(grantType.equals(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE)) {
            String code = params.get("code");
            if(code == null){
                log.debug("Parameter 'code' is missing.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            Token token = serverServices.getTokenManager().getAuthorizationCodes().getToken(code);
            if(token == null){
                log.debug("Code is invalid.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            params.put(Constants.PARAMETER_SCOPE, token.getScope());
        }

        if (grantType.equals(Constants.PARAMETER_VALUE_DEVICE_CODE)) {
            String deviceCode = params.get(Constants.PARAMETER_DEVICE_CODE);
            if (deviceCode == null) {
                log.debug("Parameter device_code is missing.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }

            Token token = serverServices.getTokenManager().getDeviceCodes().getToken(deviceCode);

            if (token == null) {

                token = serverServices.getTokenManager().getDeviceCodes().getToken("pre:" + deviceCode);

                if (token == null) {
                    log.debug("Device Code is invalid.");
                    exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                    return;
                }

                if (token.isExpired()) {
                    log.debug("Device Code is expired.");
                    exc.setResponse(answerWithError(400, Constants.ERROR_EXPIRED_TOKEN));
                    return;
                }

                if (!token.getClientId().equals(clientId)) {
                    log.debug("Device Code belongs to one client ('" + token.getClientId() + "') while token was requested from a different client ('" + clientId + "').");
                    exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_CLIENT));
                    return;
                }

                exc.setResponse(answerWithError(400, Constants.ERROR_AUTHORIZATION_PENDING));
                return;
            }

            if (token.isExpired()) {
                log.debug("Device Code is expired.");
                exc.setResponse(answerWithError(400, Constants.ERROR_EXPIRED_TOKEN));
                return;
            }

            if (!token.getClientId().equals(clientId)) {
                log.debug("Device Code belongs to one client ('" + token.getClientId() + "') while token was requested from a different client ('" + clientId + "').");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            ctx = serverServices.getProvidedServices().getGrantContextProvider().findById(token.getValue()).get();
            params.put(Constants.PARAMETER_SCOPE, ctx.getValue(Constants.PARAMETER_SCOPE));
            copyDeviceCodeIntoContext(token,ctx);
        }

        String scopes = params.get(Constants.PARAMETER_SCOPE);
        if(scopes == null && grantType.equals(Constants.PARAMETER_VALUE_REFRESH_TOKEN) && params.get(Constants.PARAMETER_REFRESH_TOKEN) != null) {
            String maybeRefreshToken = params.get(Constants.PARAMETER_REFRESH_TOKEN);
            if (!serverServices.getTokenManager().getRefreshTokens().tokenExists(maybeRefreshToken)) {
                log.debug("RefreshToken is not known.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            scopes = serverServices.getTokenManager().getRefreshTokens().getToken(maybeRefreshToken).getScope();
        }

        if (!serverServices.getSupportedScopes().scopesSupported(scopes) || scopeIsSuperior(session.getValue(Constants.PARAMETER_SCOPE), scopes)) {
            log.debug("Scope '" + scopes + "' from parameter is not supported or is supperior to session scope.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_SCOPE));
            return;
        }
        ctx.putValue(Constants.PARAMETER_SCOPE, scopes);

        if (grantType.equals(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE)) {
            Token token = serverServices.getTokenManager().getAuthorizationCodes().getToken(params.get(Constants.PARAMETER_CODE));
            if (params.get(Constants.PARAMETER_REDIRECT_URI) == null || !token.getRedirectUri().equals(params.get(Constants.PARAMETER_REDIRECT_URI)) || params.get(Constants.PARAMETER_CODE) == null) {
                log.debug("Parameter redirect_uri does not match the token's redirect_uri.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            String code = params.get(Constants.PARAMETER_CODE);
            if (!serverServices.getTokenManager().getAuthorizationCodes().tokenExists(code)) {
                log.debug("Code is invalid.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            Token authorizationCodeToken = serverServices.getTokenManager().getAuthorizationCodes().getToken(code);

            if (authorizationCodeToken.getUsages() > 0) {
                authorizationCodeToken.revokeCascade();
                log.debug("Code has already been used, revoking all child tokens.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (authorizationCodeToken.isExpired()) {
                log.debug("Code is expired.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (!authorizationCodeToken.getClientId().equals(clientId)) {
                log.debug("Code does not fit to the clientId.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            Set<String> redirectUri = serverServices.getProvidedServices().getClientDataProvider().getRedirectUris(clientId);
            if (!redirectUri.contains(params.get(Constants.PARAMETER_REDIRECT_URI))) {
                log.debug("Parameter redirect_uri does not match one of the client's redirect_uris.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            ctx.putValue(Constants.SESSION_AUTHORIZATION_CODE, code);
            copyAuthorizationCodeIntoContext(authorizationCodeToken,ctx);

        }

        if (grantType.equals(Constants.PARAMETER_VALUE_PASSWORD)) {
            if (params.get(Constants.PARAMETER_USERNAME) == null || params.get(Constants.PARAMETER_PASSWORD) == null) {
                log.debug("Parameter username or password missing.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            if(!serverServices.getProvidedServices().getUserDataProvider().verifyUser(params.get(Constants.PARAMETER_USERNAME), params.get(Constants.PARAMETER_PASSWORD))){
                log.debug("Parameter username or password incorrect.");
                exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
                return;
            }
            session.putValue(Constants.PARAMETER_USERNAME, params.get(Constants.PARAMETER_USERNAME));
        }

        if (grantType.equals(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS))
            if (!clientIsAuthorized) {
                log.debug("Client is not authorized.");
                exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
                return;
            }
        if (grantType.equals(Constants.PARAMETER_VALUE_REFRESH_TOKEN)) {
            if (params.get(Constants.PARAMETER_REFRESH_TOKEN) == null) {
                log.debug("Parameter refresh_token is missing.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            String refreshToken = params.get(Constants.PARAMETER_REFRESH_TOKEN);
            if (!serverServices.getTokenManager().getRefreshTokens().tokenExists(refreshToken)) {
                log.debug("RefreshToken is not known.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            Token refreshTokenToken = serverServices.getTokenManager().getRefreshTokens().getToken(refreshToken);

            if (configProvider != null && configProvider.useReusableRefreshTokens(new TokenContext(clientId))) {
                if (refreshTokenToken.isExpired()) {
                    log.debug("RefreshToken is expired.");
                    exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                    return;
                }
            } else {
                if (refreshTokenToken.getUsages() > 0) {
                    refreshTokenToken.revokeCascade();
                    log.debug("RefreshToken has already been used, revoking all child tokens.");
                    exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                    return;
                }

                if (refreshTokenToken.isExpired() || refreshTokenToken.getUsages() > 1) {
                    log.debug("RefreshToken is expired.");
                    exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                    return;
                }
            }

            if (!refreshTokenToken.getClientId().equals(clientId)) {
                log.debug("RefreshToken does not fit to the clientId.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            ctx.putValue(Constants.PARAMETER_REFRESH_TOKEN, refreshToken);
            copyRefreshTokenIntoContext(refreshTokenToken,ctx);
        }


        // request is now valid

        copyParamsIntoContext(params, ctx);

        //log.info("Valid Token Request");
        ctx.putValue(Constants.SESSION_ENDPOINT, Constants.ENDPOINT_TOKEN);

        String response = Constants.TOKEN_TYPE_TOKEN;
        if (hasOpenIdScope(ctx))
            response += " " + Constants.TOKEN_TYPE_ID_TOKEN;
        ctx.putValue(Constants.PARAMETER_RESPONSE_TYPE, response);

        Map<String, String> responseBody = new CombinedResponseGenerator(serverServices, ctx).invokeResponse(response);
        exc.setResponse(okWithJSONBody(responseBody));
    }

    private void copyDeviceCodeIntoContext(Token deviceCode, GrantContext ctx) {
        copyBaseIntoContext(deviceCode,ctx);
        ctx.putValue(Constants.PARAMETER_VALUE_DEVICE_CODE, deviceCode.getValue());
    }

    private void copyAuthorizationCodeIntoContext(Token authorizationCodeToken, GrantContext ctx) {
        copyBaseIntoContext(authorizationCodeToken,ctx);
        ctx.putValue(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE, authorizationCodeToken.getValue());
    }

    private void copyRefreshTokenIntoContext(Token refreshToken, GrantContext ctx) {
        copyBaseIntoContext(refreshToken,ctx);
        ctx.putValue(Constants.PARAMETER_REFRESH_TOKEN, refreshToken.getValue());
    }

    private void copyBaseIntoContext(Token token, GrantContext ctx){
        ctx.putValue(Constants.PARAMETER_USERNAME,token.getUsername());
        ctx.putValue(Constants.PARAMETER_CLIENT_ID,token.getClientId());
        ctx.putValue(Constants.PARAMETER_CLAIMS,token.getClaims());
        ctx.putValue(Constants.PARAMETER_SCOPE,token.getScope());
        ctx.putValue(Constants.PARAMETER_REDIRECT_URI,token.getRedirectUri());
    }

    private void copyParamsIntoContext(Map<String, String> params, GrantContext ctx) {
        params.keySet().stream().forEach(key -> {
            try {
                ctx.putValue(key, params.get(key));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private boolean scopeIsSuperior(String oldScope, String newScope) {
        if (oldScope == null)
            return false;
        Set<String> oldScopes = Stream.of(oldScope.split(Pattern.quote(" "))).collect(Collectors.toSet());
        Set<String> newScopes = Stream.of(newScope.split(Pattern.quote(" "))).collect(Collectors.toSet());

        for (String scope : newScopes)
            if (!oldScopes.contains(scope))
                return true;

        return false;
    }

    private boolean grantTypeIsSupported(String grantType) {
        HashSet<String> supportedGrantTypes = new HashSet<>();
        if(configProvider.getActiveGrantsConfiguration().isAuthorizationCode())
            supportedGrantTypes.add(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE);
        if(configProvider.getActiveGrantsConfiguration().isResourceOwnerPasswordCredentials())
            supportedGrantTypes.add(Constants.PARAMETER_VALUE_PASSWORD);
        if(configProvider.getActiveGrantsConfiguration().isClientCredentials())
            supportedGrantTypes.add(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS);
        if(configProvider.getActiveGrantsConfiguration().isRefreshToken())
            supportedGrantTypes.add(Constants.PARAMETER_VALUE_REFRESH_TOKEN);
        if(configProvider.getActiveGrantsConfiguration().isDeviceAuthorization())
            supportedGrantTypes.add(Constants.PARAMETER_VALUE_DEVICE_CODE);
        return supportedGrantTypes.contains(grantType);
    }
}
