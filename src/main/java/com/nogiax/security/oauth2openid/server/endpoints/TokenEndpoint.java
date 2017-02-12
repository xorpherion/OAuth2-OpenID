package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.*;
import com.nogiax.security.oauth2openid.token.Token;
import com.nogiax.security.oauth2openid.tokenanswers.CombinedResponseGenerator;

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
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        if (!clientIsAuthorized && serverServices.getProvidedServices().getClientDataProvider().isConfidential(clientId)) {
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        session.putValue(Constants.PARAMETER_CLIENT_ID, clientId);

        if (params.get(Constants.PARAMETER_GRANT_TYPE) == null || params.get(Constants.PARAMETER_SCOPE) == null) {
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        String grantType = params.get(Constants.PARAMETER_GRANT_TYPE);
        if (!grantTypeIsSupported(grantType)) {
            exc.setResponse(answerWithError(400, Constants.ERROR_UNSUPPORTED_GRANT_TYPE));
            return;
        }
        session.putValue(Constants.PARAMETER_GRANT_TYPE, grantType);


        if (grantType.equals(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE)) {
            String code = params.get(Constants.PARAMETER_CODE);
            if (params.get(Constants.PARAMETER_REDIRECT_URI) == null || !session.getValue(Constants.PARAMETER_REDIRECT_URI).equals(params.get(Constants.PARAMETER_REDIRECT_URI)) || params.get(Constants.PARAMETER_CODE) == null) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            if (!serverServices.getTokenManager().getAuthorizationCodes().tokenExists(code)) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            Token authorizationCodeToken = serverServices.getTokenManager().getAuthorizationCodes().getToken(code);

            if (authorizationCodeToken.getUsages() > 0) {
                authorizationCodeToken.revokeCascade();
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (authorizationCodeToken.isExpired() || authorizationCodeToken.getUsages() > 1) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (!authorizationCodeToken.getClientId().equals(clientId)) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            String redirectUri = serverServices.getProvidedServices().getClientDataProvider().getRedirectUri(clientId);
            if (!redirectUri.equals(params.get(Constants.PARAMETER_REDIRECT_URI))) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            session.putValue(Constants.SESSION_AUTHORIZATION_CODE, code);


        }

        if (grantType.equals(Constants.PARAMETER_VALUE_PASSWORD)) {
            if (params.get(Constants.PARAMETER_USERNAME) == null || params.get(Constants.PARAMETER_PASSWORD) == null || !serverServices.getProvidedServices().getUserDataProvider().verifyUser(params.get(Constants.PARAMETER_USERNAME), params.get(Constants.PARAMETER_PASSWORD))) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }
            session.putValue(Constants.PARAMETER_USERNAME, params.get(Constants.PARAMETER_USERNAME));
        }

        if (grantType.equals(Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS))
            if (!clientIsAuthorized) {
                exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
                return;
            }
        if (grantType.equals(Constants.PARAMETER_VALUE_REFRESH_TOKEN)) {
            String refreshToken = params.get(Constants.PARAMETER_REFRESH_TOKEN);
            if (params.get(Constants.PARAMETER_REFRESH_TOKEN) == null) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
                return;
            }

            if (!serverServices.getTokenManager().getRefreshTokens().tokenExists(refreshToken)) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            Token refreshTokenToken = serverServices.getTokenManager().getRefreshTokens().getToken(refreshToken);

            if (refreshTokenToken.getUsages() > 0) {
                refreshTokenToken.revokeCascade();
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (refreshTokenToken.isExpired() || refreshTokenToken.getUsages() > 1) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }

            if (!refreshTokenToken.getClientId().equals(clientId)) {
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_GRANT));
                return;
            }
            session.putValue(Constants.PARAMETER_REFRESH_TOKEN, refreshToken);
        }

        if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE)) || scopeIsSuperior(session.getValue(Constants.PARAMETER_SCOPE), params.get(Constants.PARAMETER_SCOPE))) {
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_SCOPE));
            return;
        }
        session.putValue(Constants.PARAMETER_SCOPE, params.get(Constants.PARAMETER_SCOPE));

        // request is now valid

        //log.info("Valid Token Request");
        session.putValue(Constants.SESSION_ENDPOINT, Constants.ENDPOINT_TOKEN);

        String response = Constants.TOKEN_TYPE_TOKEN;
        if (hasOpenIdScope(exc) && session.getValue(Constants.PARAMETER_SCOPE).contains(Constants.SCOPE_OPENID))
            response += " " + Constants.TOKEN_TYPE_ID_TOKEN;
        session.putValue(Constants.PARAMETER_RESPONSE_TYPE,response);

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
