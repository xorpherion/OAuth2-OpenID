package com.nogiax.security.oauth2openid.server.endpoints;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nogiax.http.Exchange;
import com.nogiax.http.Response;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.BodyUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;

import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class LoginEndpoint extends Endpoint {

    public LoginEndpoint(ServerServices serverServices) {
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
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        if (!params.containsKey(Constants.LOGIN_CONSENT) || params.get(Constants.LOGIN_CONSENT).equals(Constants.VALUE_NO)) {
            exc.setResponse(redirectToCallbackWithError(session.getValue(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_ACCESS_DENIED, session.getValue(Constants.SESSION_LOGIN_STATE), setToResponseModeOrUseDefault(exc, session)));
            return;
        }

        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(session.getValue(Constants.SESSION_LOGIN_STATE))) {
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(session)));
            return;
        }
        session.putValue(Constants.SESSION_CONSENT_GIVEN, Constants.VALUE_YES);
        exc.setResponse(redirectToAfterLoginEndpoint());
    }

    private Response redirectToAfterLoginEndpoint() {
        return new ResponseBuilder()
                .redirectTempWithGet(Constants.ENDPOINT_AFTER_LOGIN).build();
    }

    private void checkLogin(Exchange exc) throws Exception {
        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());
        if (!params.containsKey(Constants.LOGIN_USERNAME) && !params.containsKey(Constants.LOGIN_PASSWORD)) {
            Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(session)));
            return;
        }
        String username = params.get(Constants.LOGIN_USERNAME);
        String password = params.get(Constants.LOGIN_PASSWORD);
        if (!serverServices.getProvidedServices().getUserDataProvider().verifyUser(username, password)) {
            serverServices.getProvidedServices().getUserDataProvider().badLogin(username);
            Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(couldNotVerifyUserError(session)));
            return;
        }
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        if (params.get(Constants.SESSION_LOGIN_STATE) == null || !params.get(Constants.SESSION_LOGIN_STATE).equals(session.getValue(Constants.SESSION_LOGIN_STATE))) {
            serverServices.getProvidedServices().getUserDataProvider().badLogin(username);
            session.putValue(Constants.SESSION_REDIRECT_FROM_ERROR, Constants.VALUE_YES);
            exc.setResponse(redirectToLogin(possibleCSRFError(session)));
            return;
        }
        session.putValue(Constants.LOGIN_USERNAME, username);
        session.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);
        session.putValue(Constants.PARAMETER_AUTH_TIME, String.valueOf(Instant.now().getEpochSecond()));
        exc.setResponse(redirectToConsent(getConsentPageParams(session)));
    }

    private Map<String, String> possibleCSRFError(Session session) throws Exception {
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
