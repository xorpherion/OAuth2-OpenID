package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.responsegenerators.CombinedResponseGenerator;
import com.bornium.security.oauth2openid.server.AuthorizationServer;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationEndpoint extends Endpoint {

    public AuthorizationEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_AUTHORIZATION, Constants.ENDPOINT_AFTER_LOGIN);
    }


    private boolean redirectUriOrClientIdProblem(Map<String, String> params) {
        return params.get(Constants.PARAMETER_REDIRECT_URI) == null
                || !Parameters.redirectUriIsAbsolute(params.get(Constants.PARAMETER_REDIRECT_URI))
                || params.get(Constants.PARAMETER_CLIENT_ID) == null
                || !serverServices.getProvidedServices().getClientDataProvider().getRedirectUris(params.get(Constants.PARAMETER_CLIENT_ID)).contains(params.get(Constants.PARAMETER_REDIRECT_URI))
                || !clientExists(params.get(Constants.PARAMETER_CLIENT_ID));
    }


    @Override
    public void invokeOn(Exchange exc) throws Exception {
        //log.info("Authorization endpoint oauth2");
        Map<String, String> params = getParams(exc);

        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        GrantContext ctx = serverServices.getProvidedServices().getGrantContextDaoProvider().findByIdOrCreate(params.get(Constants.GRANT_CONTEXT_ID));

        if (requestTargetsTheAuthorizationEndpoint(exc)) {
            if (redirectUriOrClientIdProblem(params)) {
                log.debug("Parameters client_id ('" + params.get(Constants.PARAMETER_CLIENT_ID) + "') or redirect_uri ('" + params.get(Constants.PARAMETER_REDIRECT_URI) + "') have problems.");
                exc.setResponse(informResourceOwnerError(Constants.ERROR_INVALID_REQUEST));
                return;
            }

            if (params.get(Constants.PARAMETER_RESPONSE_TYPE) == null) {
                log.debug("Parameter response_type is missing.");
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE), false));
                return;
            }

            if (!responseTypeIsSupported(params.get(Constants.PARAMETER_RESPONSE_TYPE))) {
                log.debug("ResponseType ('" + params.get(Constants.PARAMETER_RESPONSE_TYPE) + "') is not supported.");
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE, params.get(Constants.PARAMETER_STATE), false));
                return;
            }
            ctx.putValue(Constants.PARAMETER_RESPONSE_TYPE, params.get(Constants.PARAMETER_RESPONSE_TYPE));
            if(params.get(Constants.PARAMETER_RESPONSE_MODE) != null)
                ctx.putValue(Constants.PARAMETER_RESPONSE_MODE, params.get(Constants.PARAMETER_RESPONSE_MODE));

            if (hasOpenIdScope(exc))
                if (isImplicitFlowAndHasNoNonceValue(params)) {
                    log.debug("Implicit Flow is used, but no nonce value present.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                    return;
                }

            if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE))) {
                log.debug("Scope ('" + params.get(Constants.PARAMETER_SCOPE) + "') not supported.");
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_SCOPE, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                return;
            }

            if (isLoggedIn(ctx) && hasAMaximumAuthenticationAgeFromBefore(session)) {
                Duration maxAge = Duration.ofSeconds(Integer.parseInt(session.getValue(Constants.PARAMETER_MAX_AGE)));
                if (Instant.now().isAfter(Instant.ofEpochSecond(Long.parseLong(session.getValue(Constants.PARAMETER_AUTH_TIME))).plus(maxAge)))
                    session.clear();
            }

            if (hasOpenIdScope(exc)) {
                if (params.get(Constants.PARAMETER_PROMPT) != null) {
                    String prompt = params.get(Constants.PARAMETER_PROMPT);
                    if (prompt.equals(Constants.PARAMETER_VALUE_LOGIN))
                        session.clear();
                    if (prompt.equals(Constants.PARAMETER_VALUE_NONE))
                        if (!isLoggedInAndHasGivenConsent(ctx)) {
                            log.debug("Session is not logged in or has not given consent.");
                            exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INTERACTION_REQUIRED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                            return;
                        }
                }
                if (params.get(Constants.PARAMETER_MAX_AGE) != null) {
                    try {
                        int maxAge = Integer.parseInt(params.get(Constants.PARAMETER_MAX_AGE));
                        if (maxAge < 0)
                            throw new RuntimeException(); // exception is used as control flow only because Integer.parseInt throws anyway on error
                    } catch (Exception e) {
                        log.debug("MaxAge ('" + params.get(Constants.PARAMETER_MAX_AGE) + "') has a problem.");
                        exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                        return;
                    }
                }

                if (params.containsKey(Constants.PARAMETER_REQUEST)) {
                    log.debug("Parameter 'request' not supported with OpenId Scope.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                    return;
                }
                if (params.containsKey(Constants.PARAMETER_REQUEST_URI)) {
                    log.debug("Parameter 'request_uri' not supported with OpenId Scope.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_URI_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
                    return;
                }
            }

            copyParametersIntoContext(ctx, params);
            if (!isLoggedInAndHasGivenConsent(ctx)) {
                exc.setResponse(associatedContextWithClientStateAndInformLoginEndpoint(params, ctx));
                return;
            }
            answerWithToken(exc, ctx);
        } else {
            // this is ENDPOINT_AFTER_LOGIN
            if (isLoggedInAndHasGivenConsent(ctx)) {
                serverServices.getProvidedServices().getGrantContextDaoProvider().invalidate(ctx.getIdentifier());
                answerWithToken(exc, ctx);
            } else {
                log.debug("Session is not logged in or has not given consent.");
                exc.setResponse(redirectToCallbackWithError(session.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED, session.getValue(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(exc, ctx)));
            }
        }

    }

    private Response associatedContextWithClientStateAndInformLoginEndpoint(Map<String, String> params, GrantContext ctx) {
        ctx.setIdentifier(params.get(Constants.PARAMETER_STATE));
        serverServices.getProvidedServices().getGrantContextDaoProvider().persist(ctx);
        return serverServices.getLoginEndpoint().initiateLoginAndConsent(ctx.getIdentifier());
    }

    private boolean isImplicitFlowAndHasNoNonceValue(Map<String, String> params) {
        return params.get(Constants.PARAMETER_RESPONSE_TYPE).equals(Constants.PARAMETER_VALUE_TOKEN) && params.get(Constants.PARAMETER_NONCE) == null;
    }

    private boolean hasAMaximumAuthenticationAgeFromBefore(Session session) throws Exception {
        return session.getValue(Constants.PARAMETER_MAX_AGE) != null;
    }

    private boolean requestTargetsTheAuthorizationEndpoint(Exchange exc) {
        return exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_AUTHORIZATION);
    }

    private boolean responseTypeIsSupported(String responseType) {
        HashSet<String> supported = new HashSet<>();
        supported.add(Constants.PARAMETER_VALUE_CODE);
        supported.add(Constants.PARAMETER_VALUE_TOKEN);
        supported.add(Constants.PARAMETER_VALUE_ID_TOKEN);
        supported.add(Constants.PARAMETER_VALUE_NONE);

        String[] responseTypes = responseType.split(Pattern.quote(" "));
        for (String rType : responseTypes)
            if (!supported.contains(rType))
                return false;
        return true;
    }

    private void copyParametersIntoContext(GrantContext ctx, Map<String, String> params) throws Exception {
        for (String param : params.keySet())
            ctx.putValue(param, params.get(param));
    }

    private void answerWithToken(Exchange exc, GrantContext ctx) throws Exception {
        //System.out.println("logged in and consent");
        ctx.putValue(Constants.SESSION_ENDPOINT, Constants.ENDPOINT_AUTHORIZATION);
        String responseType = ctx.getValue(Constants.PARAMETER_RESPONSE_TYPE);

        boolean useFragment = setToResponseModeOrUseDefault(exc, ctx, responseType.contains(Constants.PARAMETER_VALUE_TOKEN));

        Map<String, String> callbackParams = new CombinedResponseGenerator(serverServices, ctx).invokeResponse(responseTypeToResponseGeneratorValue(responseType));
        ctx.setIdentifier(callbackParams.get(Constants.PARAMETER_CODE));
        serverServices.getProvidedServices().getGrantContextDaoProvider().persist(ctx);
        exc.setResponse(redirectToCallbackWithParams(ctx.getValue(Constants.PARAMETER_REDIRECT_URI), callbackParams, ctx.getValue(Constants.PARAMETER_STATE), useFragment));
    }


    private String responseTypeToResponseGeneratorValue(String responseType) {
        StringBuilder builder = new StringBuilder();

        String copy = responseType;

        if (copy.contains(Constants.PARAMETER_VALUE_CODE)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_CODE, "").trim();
            builder.append(Constants.TOKEN_TYPE_CODE).append(" ");
        }
        if (copy.contains(Constants.PARAMETER_VALUE_ID_TOKEN)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_ID_TOKEN, "").trim();
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");
        }
        if (copy.contains(Constants.PARAMETER_VALUE_TOKEN)) {
            copy = copy.replace(Constants.PARAMETER_VALUE_TOKEN, "").trim();
            builder.append(Constants.TOKEN_TYPE_ID_TOKEN).append(" ");
        }


        return builder.toString().trim();

    }


    @Override
    public String getScope(Exchange exc) throws Exception {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
        if (!params.isEmpty() && params.get(Constants.PARAMETER_SCOPE) != null)
            return params.get(Constants.PARAMETER_SCOPE);
        return serverServices.getProvidedServices().getSessionProvider().getSession(exc).getValue(Constants.PARAMETER_SCOPE);
    }


}
