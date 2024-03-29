package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.ActiveGrantsConfiguration;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.responsegenerators.CombinedResponseGenerator;
import com.bornium.security.oauth2openid.server.AuthorizationServer;

import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.Instant;
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
        GrantContext ctx = serverServices.getProvidedServices().getGrantContextProvider().findByIdOrCreate(params.get(Constants.GRANT_CONTEXT_ID));

        if(ctx.getIdentifier() == null)
            copyParametersIntoContext(ctx,params); // possibly a dangerous line if any parameter check is missing

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

            if (hasOpenIdScope(ctx))
                if (isImplicitFlowAndHasNoNonceValue(params)) {
                    log.debug("Implicit Flow is used, but no nonce value present.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                    return;
                }

            if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE))) {
                log.debug("Scope ('" + params.get(Constants.PARAMETER_SCOPE) + "') not supported.");
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_SCOPE, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                return;
            }

            if (isLoggedIn(session) && hasAMaximumAuthenticationAgeFromBefore(session)) {
                Duration maxAge = Duration.ofSeconds(Integer.parseInt(session.getValue(Constants.PARAMETER_MAX_AGE)));
                if (Instant.now().isAfter(Instant.ofEpochSecond(Long.parseLong(session.getValue(Constants.PARAMETER_AUTH_TIME))).plus(maxAge)))
                    session.clear();
            }

            if (hasOpenIdScope(ctx)) {
                if (params.get(Constants.PARAMETER_PROMPT) != null) {
                    String prompt = params.get(Constants.PARAMETER_PROMPT);
                    if (prompt.equals(Constants.PARAMETER_VALUE_LOGIN))
                        session.clear();
                    if (prompt.equals(Constants.PARAMETER_VALUE_NONE))
                        if (!isLoggedInAndHasGivenConsent(session,ctx)) {
                            log.debug("Session is not logged in or has not given consent.");
                            exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INTERACTION_REQUIRED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                            return;
                        }
                }
                if (params.get(Constants.PARAMETER_MAX_AGE) != null) {
                    try {
                        int maxAge = Integer.parseInt(params.get(Constants.PARAMETER_MAX_AGE));
                        if (maxAge < 0)
                            throw new RuntimeException(); // exception is used as control flow only because Integer.parseInt throws anyway on error
                        session.putValue(Constants.PARAMETER_MAX_AGE, String.valueOf(maxAge));
                    } catch (Exception e) {
                        log.debug("MaxAge ('" + params.get(Constants.PARAMETER_MAX_AGE) + "') has a problem.");
                        exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                        return;
                    }

                }

                if (params.containsKey(Constants.PARAMETER_REQUEST)) {
                    log.debug("Parameter 'request' not supported with OpenId Scope.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                    return;
                }
                if (params.containsKey(Constants.PARAMETER_REQUEST_URI)) {
                    log.debug("Parameter 'request_uri' not supported with OpenId Scope.");
                    exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_REQUEST_URI_NOT_SUPPORTED, params.get(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
                    return;
                }
            }

            copyParametersIntoContext(ctx, params);
            if (!isLoggedInAndHasGivenConsent(session,ctx)) {
                associateContextWithClientStateAndInformLoginEndpoint(params, ctx, exc);
                return;
            }
            answerWithToken(exc, ctx);
        } else {
            // this is ENDPOINT_AFTER_LOGIN
            if (isLoggedInAndHasGivenConsent(session,ctx)) {
                serverServices.getProvidedServices().getGrantContextProvider().invalidationHint(ctx.getIdentifier());
                answerWithToken(exc, ctx);
            } else {
                log.debug("Session is not logged in or has not given consent.");
                exc.setResponse(redirectToCallbackWithError(session.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED, session.getValue(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
            }
        }

    }

    private void associateContextWithClientStateAndInformLoginEndpoint(Map<String, String> params, GrantContext ctx, Exchange exc) {
        ctx.setIdentifier(params.get(Constants.PARAMETER_STATE));
        serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
        serverServices.getProvidedServices().getAuthenticationProvider().initiateAuthenticationAndConsent(ctx.getIdentifier(), false, exc, serverServices, loginResult -> {
            GrantContext context = serverServices.getProvidedServices().getGrantContextProvider().findById(loginResult.getGrantContextId()).get();

            context.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);
            context.putValue(Constants.LOGIN_USERNAME, loginResult.getAuthenticatedUser().get());
            context.putValue(Constants.PARAMETER_AUTH_TIME, String.valueOf(Instant.now().getEpochSecond()));

            serverServices.getProvidedServices().getGrantContextProvider().persist(context);

            if(!loginResult.getConsentContext().isConsented()){
                try {
                    loginResult.getCurrentRunningExchange().setResponse(redirectToCallbackWithError(context.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED, context.getValue(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(context)));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                return;
            }

            serverServices.getProvidedServices().getConsentProvider().persist(loginResult.getConsentContext());
            loginResult.getCurrentRunningExchange().setResponse(redirectToAfterLoginEndpoint(context));
        });
    }

    private Response redirectToAfterLoginEndpoint(GrantContext ctx) {
        try {
            return new ResponseBuilder()
                    .redirectTempWithGet(this.serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_AFTER_LOGIN + "?" + Constants.GRANT_CONTEXT_ID + "=" + UriUtil.encode(ctx.getIdentifier())).build();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
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
        ActiveGrantsConfiguration activeGrants = serverServices.getProvidedServices().getConfigProvider().getActiveGrantsConfiguration();

        if(activeGrants.isAuthorizationCode())
            supported.add(Constants.PARAMETER_VALUE_CODE);
        if(activeGrants.isImplicit())
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

        boolean useFragment = setToResponseModeOrUseDefault(ctx, responseType.contains(Constants.PARAMETER_VALUE_TOKEN));

        Map<String, String> callbackParams = new CombinedResponseGenerator(serverServices, ctx).invokeResponse(responseTypeToResponseGeneratorValue(responseType));
        if(!callbackParams.isEmpty()) {
            ctx.setIdentifier(findCtxIdentifierInTokenResponse(callbackParams));
            serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
        }
        exc.setResponse(redirectToCallbackWithParams(ctx.getValue(Constants.PARAMETER_REDIRECT_URI), callbackParams, ctx.getValue(Constants.PARAMETER_STATE), useFragment));
    }

    private String findCtxIdentifierInTokenResponse(Map<String, String> callbackParams) {
        String authCode = callbackParams.get(Constants.PARAMETER_CODE);
        if(authCode != null)
            return authCode;

        String accessToken = callbackParams.get(Constants.PARAMETER_ACCESS_TOKEN);
        if(accessToken != null)
            return accessToken;

        String idToken = callbackParams.get(Constants.PARAMETER_ID_TOKEN);
        if(idToken != null)
            return idToken;

        throw new RuntimeException("Should not happen");
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
}
