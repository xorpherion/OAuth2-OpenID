package com.nogiax.security.oauth2openid.server.endpoints;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nogiax.http.Exchange;
import com.nogiax.http.Response;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.BodyUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.Session;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class LoginEndpoint extends Endpoint {

    public LoginEndpoint(ServerProvider serverProvider) {
        super(serverProvider, Constants.ENDPOINT_LOGIN, Constants.ENDPOINT_CONSENT);
    }

    @Override
    public boolean invokeOnOAuth2(Exchange exc) throws Exception {
        log.info("Login endpoint");
        if (exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_LOGIN)) {
            if (!wasRedirectFromError(exc) && hasSentLoginData(exc))
                return checkLogin(exc);
            else
                exc.setResponse(sendLoginpage());
        } else if (exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_CONSENT)) {
            if (!wasRedirectFromError(exc) && hasSentConsent(exc)) {
                return checkConsent(exc);
            } else
                exc.setResponse(sendConsentpage());
        }

        return true;
    }

    private boolean checkConsent(Exchange exc) throws Exception {
        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());
        Session session = serverProvider.getSessionProvider().getSession(exc);
        if (!params.containsKey(Constants.LOGIN_CONSENT) || params.get(Constants.LOGIN_CONSENT).equals(Constants.VALUE_NO)) {
            exc.setResponse(redirectToCallbackWithError(session.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED));
            return false;
        }

        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(session.getValue(Constants.SESSION_LOGIN_STATE))) {
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(session)));
            return false;
        }
        session.putValue(Constants.SESSION_CONSENT_GIVEN, Constants.VALUE_YES);
        exc.setResponse(redirectToAuthEndpoint());
        return true;
    }

    private Response redirectToAuthEndpoint() {
        return new ResponseBuilder()
                .redirectTemp(Constants.ENDPOINT_AUTHORIZATION).build();
    }

    private boolean checkLogin(Exchange exc) throws Exception {
        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());
        if (!params.containsKey(Constants.LOGIN_USERNAME) && !params.containsKey(Constants.LOGIN_PASSWORD)) {
            Session session = serverProvider.getSessionProvider().getSession(exc);
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(session)));
            return false;
        }
        String username = params.get(Constants.LOGIN_USERNAME);
        String password = params.get(Constants.LOGIN_PASSWORD);
        if (!serverProvider.getUserDataProvider().verifyUser(username, password)) {
            Session session = serverProvider.getSessionProvider().getSession(exc);
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(session)));
            return false;
        }
        Session session = serverProvider.getSessionProvider().getSession(exc);
        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(session.getValue(Constants.SESSION_LOGIN_STATE))) {
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(session)));
            return false;
        }

        session.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);
        exc.setResponse(redirectToConsent(getConsentPageParams(session)));
        return true;
    }

    private Map<String, String> possibleCSRFError(Session session) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(session));
        result.put(Constants.PARAMETER_ERROR, Constants.ERROR_POSSIBLE_CSRF);
        return result;
    }

    private boolean wasRedirectFromError(Exchange exc) throws Exception {
        Session session = serverProvider.getSessionProvider().getSession(exc);
        String val = session.getValue(Constants.SESSION_REDIRECT_FROM_ERROR);
        if (val != null && val.equals(Constants.VALUE_YES)) {
            session.removeValue(Constants.SESSION_REDIRECT_FROM_ERROR);
            return true;
        }
        return false;
    }

    private Map<String, String> couldNotVerifyUserError(Session session) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(session));
        result.put(Constants.PARAMETER_ERROR, Constants.ERROR_COULD_NOT_VALIDATE_USER);
        return result;
    }

    private Map<String, String> getConsentPageParams(Session session) throws Exception {
        HashMap<String, String> result = new HashMap<>(prepareJsStateParameter(session));
        result.put(Constants.PARAMETER_SCOPE, session.getValue(Constants.PARAMETER_SCOPE));

        return result;
    }

    private Response sendLoginpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadLoginpage()).build();
    }

    private Response sendConsentpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadConsentpage()).build();
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
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
}
