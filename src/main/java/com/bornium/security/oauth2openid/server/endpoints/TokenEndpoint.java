package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.User;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.responsegenerators.CombinedResponseGenerator;
import com.bornium.security.oauth2openid.server.ServerServices;
import com.bornium.security.oauth2openid.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    public TokenEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_TOKEN);
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
        session.putValue(Constants.PARAMETER_CLIENT_ID, clientId);

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
        session.putValue(Constants.PARAMETER_GRANT_TYPE, grantType);

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

        if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE)) || scopeIsSuperior(session.getValue(Constants.PARAMETER_SCOPE), params.get(Constants.PARAMETER_SCOPE))) {
            log.debug("Scope '" + params.get(Constants.PARAMETER_SCOPE) + "' from parameter is not supported or is supperior to session scope.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_SCOPE));
            return;
        }
        session.putValue(Constants.PARAMETER_SCOPE, params.get(Constants.PARAMETER_SCOPE));

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
            session.putValue(Constants.SESSION_AUTHORIZATION_CODE, code);


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

            if (!refreshTokenToken.getClientId().equals(clientId)) {
                log.debug("RefreshToken does not fit to the clientId.");
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            session.putValue(Constants.PARAMETER_REFRESH_TOKEN, refreshToken);
        }


        // request is now valid

        Map<String, String> finalParams = params;
        params.keySet().stream().forEach(key -> {
            try {
                session.putValue(key, finalParams.get(key));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        //log.info("Valid Token Request");
        session.putValue(Constants.SESSION_ENDPOINT, Constants.ENDPOINT_TOKEN);

        String response = Constants.TOKEN_TYPE_TOKEN;
        if (hasOpenIdScope(exc) && session.getValue(Constants.PARAMETER_SCOPE).contains(Constants.SCOPE_OPENID))
            response += " " + Constants.TOKEN_TYPE_ID_TOKEN;
        session.putValue(Constants.PARAMETER_RESPONSE_TYPE, response);

        Map<String, String> responseBody = new CombinedResponseGenerator(serverServices, exc).invokeResponse(response);
        exc.setResponse(okWithJSONBody(responseBody));
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
        HashSet<String> supportedGrantTypes = new HashSet<String>();
        supportedGrantTypes.add(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE);
        supportedGrantTypes.add(Constants.PARAMETER_VALUE_PASSWORD);
        supportedGrantTypes.add(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS);
        supportedGrantTypes.add(Constants.PARAMETER_VALUE_REFRESH_TOKEN);
        return supportedGrantTypes.contains(grantType);
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return serverServices.getProvidedServices().getSessionProvider().getSession(exc).getValue(Constants.PARAMETER_SCOPE);
    }
}
