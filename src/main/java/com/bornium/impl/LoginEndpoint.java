package com.bornium.impl;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.BodyUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.ConsentContext;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginEndpointBase;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginResult;
import com.google.common.base.Charsets;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.io.CharStreams;

import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class LoginEndpoint extends LoginEndpointBase {

    Cache<String,String> ctxToAuthenticatedUser = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    public LoginEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_LOGIN, Constants.ENDPOINT_CONSENT);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        //log.info("Login endpoint");
        if (exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_LOGIN)) {
            if (!wasRedirectFromError(exc) && hasSentLoginData(exc))
                checkLogin(exc);
            else
                exc.setResponse(sendLoginpage());
        } else if (exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_CONSENT)) {
            if (!wasRedirectFromError(exc) && hasSentConsent(exc)) {
                checkConsent(exc);
            } else
                exc.setResponse(sendConsentpage());
        }
    }

    private void checkConsent(Exchange exc) throws Exception {
        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());
        GrantContext ctx = serverServices.getProvidedServices().getGrantContextProvider().findById(params.get(Constants.GRANT_CONTEXT_ID)).get();
        if (!params.containsKey(Constants.LOGIN_CONSENT) || params.get(Constants.LOGIN_CONSENT).equals(Constants.VALUE_NO)) {
            exc.setResponse(redirectToCallbackWithError(ctx.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED, ctx.getValue(Constants.PARAMETER_STATE), setToResponseModeOrUseDefault(ctx)));
            return;
        }

        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(ctx.getValue(Constants.SESSION_LOGIN_STATE))) {
            ctx.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(ctx)));
            return;
        }

        serverServices.getProvidedServices().getConsentProvider()
                .persist(new ConsentContext(ctx.getValue(Constants.LOGIN_USERNAME), ctx.getValue(Constants.PARAMETER_CLIENT_ID), Arrays.asList(ctx.getValue(Constants.PARAMETER_SCOPE).split(Pattern.quote(" "))).stream().collect(Collectors.toSet())));

        exc.setResponse(redirectToAfterLoginEndpoint(ctx));
    }

    private Response redirectToAfterLoginEndpoint(GrantContext ctx) {
        return new ResponseBuilder()
                .redirectTempWithGet(this.serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_AFTER_LOGIN + "?" + Constants.GRANT_CONTEXT_ID + "=" + ctx.getIdentifier()).build();
    }

    private void checkLogin(Exchange exc) throws Exception {
        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());

        GrantContext ctx = serverServices.getProvidedServices().getGrantContextProvider().findById(params.get(Constants.GRANT_CONTEXT_ID)).get();

        if (!params.containsKey(Constants.LOGIN_USERNAME) && !params.containsKey(Constants.LOGIN_PASSWORD)) {
            ctx.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(ctx)));
            return;
        }
        String username = params.get(Constants.LOGIN_USERNAME);
        String password = params.get(Constants.LOGIN_PASSWORD);
        if (!serverServices.getProvidedServices().getUserDataProvider().verifyUser(username, password)) {
            ctx.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(ctx)));
            return;
        }
        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(ctx.getValue(Constants.SESSION_LOGIN_STATE))) {
            ctx.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(ctx)));
            return;
        }

        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        session.putValue(Constants.LOGIN_USERNAME, username);
        session.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);
        session.putValue(Constants.PARAMETER_AUTH_TIME, String.valueOf(Instant.now().getEpochSecond()));

        ctxToAuthenticatedUser.put(ctx.getIdentifier(), username);

        if (ctx.getValue(Constants.PARAMETER_USER_CODE) != null)
            exc.setResponse(redirectToDeviceVerification(getDeviceVerificationPageParams(ctx)));
        else
            exc.setResponse(redirectToConsent(getConsentPageParams(ctx)));
    }

    private Map<String, String> possibleCSRFError(GrantContext session) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(session));
        result.put(Constants.PARAMETER_ERROR, Constants.ERROR_POSSIBLE_CSRF);
        return result;
    }

    private boolean wasRedirectFromError(Exchange exc) throws Exception {
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        String val = session.getValue(Constants.SESSION_REDIRECT_FROM_ERROR);
        if (val != null && val.equals(Constants.VALUE_YES)) {
            session.removeValue(Constants.SESSION_REDIRECT_FROM_ERROR);
            return true;
        }
        return false;
    }

    private Map<String, String> couldNotVerifyUserError(GrantContext session) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(session));
        result.put(Constants.PARAMETER_ERROR, Constants.ERROR_COULD_NOT_VALIDATE_USER);
        return result;
    }

    private Map<String, String> getDeviceVerificationPageParams(GrantContext ctx) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(ctx));
        result.put(Constants.PARAMETER_USER_CODE, ctx.getValue(Constants.PARAMETER_USER_CODE));
        result.put(Constants.GRANT_CONTEXT_ID, ctx.getIdentifier());

        result.entrySet().stream().forEach(e -> ctx.putValue(e.getKey(),e.getValue()));
        serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
        return result;
    }

    private Map<String, String> getConsentPageParams(GrantContext ctx) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(ctx));
        result.put(Constants.PARAMETER_SCOPE, ctx.getValue(Constants.PARAMETER_SCOPE));
        result.put(Constants.GRANT_CONTEXT_ID, ctx.getIdentifier());

        result.entrySet().stream().forEach(e -> ctx.putValue(e.getKey(),e.getValue()));
        serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);

        return result;
    }

    private Response sendLoginpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadLoginpage()).build();
    }

    private Response sendConsentpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadConsentpage()).build();
    }

    private boolean hasSentLoginData(Exchange exc) {
        if (exc.getRequest().getBody().contains(Constants.LOGIN_USERNAME) && exc.getRequest().getBody().contains(Constants.LOGIN_PASSWORD))
            return true;
        return false;
    }

    private boolean hasSentConsent(Exchange exc) {
        if (exc.getRequest().getBody().contains(Constants.LOGIN_CONSENT))
            return true;
        return false;
    }

    private String loadLoginpage() throws IOException {
        return loadPage("login.html");
    }

    private String loadConsentpage() throws IOException {
        return loadPage("consent.html");
    }

    private String loadPage(String page) throws IOException {
        return CharStreams.toString(new InputStreamReader(this.getClass().getResourceAsStream("/static/logindialog/" + page), Charsets.UTF_8));
    }

    @Override
    public Response initiateLoginAndConsent(String ctxId) {
        try {
            GrantContext ctx = serverServices.getProvidedServices().getGrantContextProvider().findById(ctxId).get();

            HashMap<String, String> params = prepareJsStateParameter(ctx);
            params.put(Constants.GRANT_CONTEXT_ID, ctx.getIdentifier());
            params.entrySet().stream().forEach(e -> {
                try {
                    ctx.putValue(e.getKey(),e.getValue());
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
            return redirectToLogin(params);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getGrantContextId(Exchange exc) {
        return getParams(exc).get(Constants.GRANT_CONTEXT_ID);
    }

    @Override
    public LoginResult getCurrentResultFor(String ctxId) {
        if(ctxId == null)
            throw new IllegalArgumentException("ctxId should not be null");

        return new LoginResult() {
            @Override
            public Optional<String> getAuthenticatedUser() {
                return Optional.ofNullable(ctxToAuthenticatedUser.getIfPresent(ctxId));
            }
        };
    }

}
