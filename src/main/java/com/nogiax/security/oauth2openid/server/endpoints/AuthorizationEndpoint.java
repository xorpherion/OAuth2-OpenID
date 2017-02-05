package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.tokenanswers.CombinedResponseGenerator;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationEndpoint extends Endpoint {

    public AuthorizationEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_AUTHORIZATION, Constants.ENDPOINT_AFTER_LOGIN);
    }


    private boolean redirectUriOrClientIdProblem(Map<String, String> params) {
        return params.get(Constants.PARAMETER_REDIRECT_URI) == null
                || !Parameters.redirectUriIsAbsolute(params.get(Constants.PARAMETER_REDIRECT_URI))
                || params.get(Constants.PARAMETER_CLIENT_ID) == null
                || !params.get(Constants.PARAMETER_REDIRECT_URI).equals(serverServices.getProvidedServices().getClientDataProvider().getRedirectUri(params.get(Constants.PARAMETER_CLIENT_ID)))
                || !clientExists(params.get(Constants.PARAMETER_CLIENT_ID));
    }


    @Override
    public void invokeOn(Exchange exc) throws Exception {
        log.info("Authorization endpoint oauth2");
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);

        if (exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_AUTHORIZATION)) {
            Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
            params = Parameters.stripEmptyParams(params);

            if (redirectUriOrClientIdProblem(params)) {
                exc.setResponse(informResourceOwnerError(Constants.ERROR_INVALID_REQUEST));
                return;
            }

            if (params.get(Constants.PARAMETER_RESPONSE_TYPE) == null || params.get(Constants.PARAMETER_CLIENT_ID) == null || params.get(Constants.PARAMETER_REDIRECT_URI) == null) {
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST));
                return;
            }

            copyParametersInSession(session, params);
            if (!isLoggedInAndHasGivenConsent(exc)) {
                HashMap<String, String> jsParams = prepareJsStateParameter(session);
                exc.setResponse(redirectToLogin(jsParams));
                return;
            }
            anserWithAuthorizationCode(exc, session);
        } else {
            // this is ENDPOINT_AFTER_LOGIN
            if (isLoggedInAndHasGivenConsent(exc)) {
                anserWithAuthorizationCode(exc, session);
            } else
                exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
        }

    }

    private void copyParametersInSession(Session session, Map<String, String> params) throws Exception {
        for (String param : params.keySet())
            session.putValue(param, params.get(param));
    }

    private void anserWithAuthorizationCode(Exchange exc, Session session) throws Exception {
        System.out.println("logged in and consent");
        String responseType = session.getValue(Constants.PARAMETER_RESPONSE_TYPE);

        Map<String, String> callbackParams = new CombinedResponseGenerator(serverServices, exc).invokeResponse(responseTypeToResponseGeneratorValue(responseType));
        exc.setResponse(redirectToCallbackWithParams(serverServices.getProvidedServices().getSessionProvider().getSession(exc).getValue(Constants.PARAMETER_REDIRECT_URI), callbackParams));
    }

    private String responseTypeToResponseGeneratorValue(String responseType) {
        StringBuilder builder = new StringBuilder();

        if (responseType.contains(Constants.PARAMETER_VALUE_CODE))
            builder.append(Constants.TOKEN_TYPE_CODE).append(" ");
        if (responseType.contains(Constants.PARAMETER_VALUE_TOKEN))
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");
        if (responseType.contains(Constants.PARAMETER_VALUE_ID_TOKEN))
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");

        return builder.toString().trim();

    }


    @Override
    public String getScope(Exchange exc) throws Exception {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
        return params.get(Constants.PARAMETER_SCOPE);
    }


}
