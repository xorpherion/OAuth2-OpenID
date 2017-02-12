package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.tokenanswers.CombinedResponseGenerator;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Pattern;

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
            if (params.isEmpty())
                params = UriUtil.queryToParameters(exc.getRequest().getBody());
            params = Parameters.stripEmptyParams(params);

            if (redirectUriOrClientIdProblem(params)) {
                exc.setResponse(informResourceOwnerError(Constants.ERROR_INVALID_REQUEST));
                return;
            }

            if (params.get(Constants.PARAMETER_RESPONSE_TYPE) == null || params.get(Constants.PARAMETER_CLIENT_ID) == null || params.get(Constants.PARAMETER_REDIRECT_URI) == null) {
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE),false));
                return;
            }

            if (!responseTypeIsSupported(params.get(Constants.PARAMETER_RESPONSE_TYPE))) {
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE, params.get(Constants.PARAMETER_STATE),false));
                return;
            }
            session.putValue(Constants.PARAMETER_RESPONSE_TYPE,params.get(Constants.PARAMETER_RESPONSE_TYPE));

            if(hasOpenIdScope(exc))
                if(params.get(Constants.PARAMETER_RESPONSE_TYPE).equals(Constants.PARAMETER_VALUE_TOKEN) && params.get(Constants.PARAMETER_NONCE) == null){
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                    return;
                }

            if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE))) {
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_SCOPE, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                return;
            }
            if(isLoggedIn(exc) && session.getValue(Constants.PARAMETER_MAX_AGE) != null){
                Duration maxAge = Duration.ofSeconds(Integer.parseInt(session.getValue(Constants.PARAMETER_MAX_AGE))); // cant throw, is only in session when it is an int
                if(Instant.now().isAfter(Instant.ofEpochSecond(Long.parseLong(session.getValue(Constants.PARAMETER_AUTH_TIME))).plus(maxAge)))
                    session.clear();
            }

            if (hasOpenIdScope(exc)) {
                if (params.get(Constants.PARAMETER_PROMPT) != null) {
                    String prompt = params.get(Constants.PARAMETER_PROMPT);
                    if (prompt.equals(Constants.PARAMETER_VALUE_LOGIN))
                        session.clear();
                    if (prompt.equals(Constants.PARAMETER_VALUE_NONE))
                        if (!isLoggedInAndHasGivenConsent(exc)) {
                            exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INTERACTION_REQUIRED, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                            return;
                        }
                }
                if(params.get(Constants.PARAMETER_MAX_AGE) != null){
                    try {
                        int maxAge = Integer.parseInt(params.get(Constants.PARAMETER_MAX_AGE));
                        if(maxAge < 0)
                            throw new RuntimeException(); // exception is used as control flow only because Integer.parseInt throws anyway on error
                    }catch(Exception e){
                        exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                        return;
                    }
                }

                if (params.containsKey(Constants.PARAMETER_REQUEST)) {
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                    return;
                }
                if (params.containsKey(Constants.PARAMETER_REQUEST_URI)) {
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_URI_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE),setToResponseModeOrUseDefault(exc,session)));
                    return;
                }
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

    private boolean responseTypeIsSupported(String responseType) {
        HashSet<String> supported = new HashSet<>();
        supported.add(Constants.PARAMETER_VALUE_CODE);
        supported.add(Constants.PARAMETER_VALUE_TOKEN);
        supported.add(Constants.PARAMETER_VALUE_ID_TOKEN);
        supported.add(Constants.PARAMETER_VALUE_NONE);

        String[] responseTypes = responseType.split(Pattern.quote(" "));
        for(String rType : responseTypes)
            if(!supported.contains(rType))
                return false;
        return true;
    }

    private void copyParametersInSession(Session session, Map<String, String> params) throws Exception {
        for (String param : params.keySet())
            session.putValue(param, params.get(param));
    }

    private void anserWithAuthorizationCode(Exchange exc, Session session) throws Exception {
        System.out.println("logged in and consent");
        String responseType = session.getValue(Constants.PARAMETER_RESPONSE_TYPE);

        boolean useFragment = setToResponseModeOrUseDefault(exc, session, responseType.contains(Constants.PARAMETER_VALUE_TOKEN));

        Map<String, String> callbackParams = new CombinedResponseGenerator(serverServices, exc).invokeResponse(responseTypeToResponseGeneratorValue(responseType));
        exc.setResponse(redirectToCallbackWithParams(session.getValue(Constants.PARAMETER_REDIRECT_URI), callbackParams, session.getValue(Constants.PARAMETER_STATE), useFragment));
    }



    private String responseTypeToResponseGeneratorValue(String responseType) {
        StringBuilder builder = new StringBuilder();

        String copy = responseType;

        if (copy.contains(Constants.PARAMETER_VALUE_CODE)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_CODE,"").trim();
            builder.append(Constants.TOKEN_TYPE_CODE).append(" ");
        }
        if (copy.contains(Constants.PARAMETER_VALUE_ID_TOKEN)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_ID_TOKEN,"").trim();
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");
        }
        if (copy.contains(Constants.PARAMETER_VALUE_TOKEN)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_TOKEN,"").trim();
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");
        }


        return builder.toString().trim();

    }


    @Override
    public String getScope(Exchange exc) throws Exception {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
        if(!params.isEmpty() && params.get(Constants.PARAMETER_SCOPE) != null)
            return params.get(Constants.PARAMETER_SCOPE);
        return serverServices.getProvidedServices().getSessionProvider().getSession(exc).getValue(Constants.PARAMETER_SCOPE);
    }


}
