package com.nogiax.security.oauth2openid.server.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.http.Response;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.permissions.ClaimsParameter;
import com.nogiax.security.oauth2openid.token.BearerTokenProvider;
import com.nogiax.security.oauth2openid.token.Token;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public abstract class Endpoint {


    Logger log = LoggerFactory.getLogger(this.getClass());

    protected final ServerServices serverServices;
    String[] paths;
    BearerTokenProvider loginStateProvider;

    public Endpoint(ServerServices serverServices, String... paths) {
        this.serverServices = serverServices;
        this.paths = paths;
        loginStateProvider = new BearerTokenProvider();
    }

    public void useIfResponsible(Exchange exc) throws Exception {
        if (isResponsible(exc))
            invokeOn(exc);
    }

    public boolean isResponsible(Exchange exc) {
        for (String path : paths)
            if (exc.getRequest().getUri().getPath().endsWith(path))
                return true;
        return false;
    }

    public abstract void invokeOn(Exchange exc) throws Exception;

    public abstract String getScope(Exchange exc) throws Exception;

    protected boolean hasOpenIdScope(String scope) {
        return scope != null && scope.contains(Constants.SCOPE_OPENID);
    }

    protected boolean hasOpenIdScope(Exchange exc) throws Exception {
        return hasOpenIdScope(getScope(exc));
    }

    protected Response informResourceOwnerError(String error) throws JsonProcessingException {
        return new ResponseBuilder().statuscode(400).body(getErrorBody(error)).build();
    }

    private String getErrorBody(String error) throws JsonProcessingException {
        HashMap<String, String> result = new HashMap<>();
        result.put(Constants.PARAMETER_ERROR, error);
        return new ObjectMapper().writeValueAsString(result);
    }

    protected boolean clientExists(String clientId) {
        return serverServices.getProvidedServices().getClientDataProvider().clientExists(clientId);
    }

    protected Response redirectToCallbackWithError(String callbackUrl, String error, String state) {
        HashMap<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_ERROR, error);
        return redirectToCallbackWithParams(callbackUrl, params, state);
    }

    protected Response redirectToCallbackWithParams(String callbackurl, Map<String, String> params, String state) {
        return redirectToCallbackWithParams(callbackurl, params, state, false);
    }

    protected Response redirectToCallbackWithParams(String callbackurl, Map<String, String> params, String state, boolean useFragment) {
        params.put(Constants.PARAMETER_STATE, state);
        return redirectToUrl(callbackurl, params, useFragment);
    }

    protected Response redirectToUrl(String url, Map<String, String> params) {
        return redirectToUrl(url, params, false);
    }

    protected Response redirectToUrl(String url, Map<String, String> params, boolean useFragment) {
        String newurl = url;
        String delimiter = "?";
        if (useFragment)
            delimiter = "#";
        params = Parameters.stripEmptyParams(params);
        if (params != null && !params.isEmpty())
            newurl += delimiter + UriUtil.parametersToQuery(params);

        return new ResponseBuilder().redirectTempWithGet(newurl).build();
    }

    protected Response redirectToLogin(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(Constants.ENDPOINT_LOGIN + "#params=" + prepareJSParams(params), null);
    }

    protected String prepareJSParams(Map<String, String> params) throws JsonProcessingException, UnsupportedEncodingException {
        String json = new ObjectMapper().writeValueAsString(params);
        return UriUtil.encode(Base64.encode(json.getBytes()));
    }

    protected boolean isLoggedIn(Exchange exc) throws Exception {
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        String loggedIn = session.getValue(Constants.SESSION_LOGGED_IN);
        return Constants.VALUE_YES.equals(loggedIn);
    }

    protected boolean hasGivenConsent(Exchange exc) throws Exception {
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        String consentGiven = session.getValue(Constants.SESSION_CONSENT_GIVEN);
        return Constants.VALUE_YES.equals(consentGiven);
    }

    protected boolean isLoggedInAndHasGivenConsent(Exchange exc) throws Exception {
        return isLoggedIn(exc) && hasGivenConsent(exc);
    }

    protected Response redirectToConsent(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(Constants.ENDPOINT_CONSENT + "#params=" + prepareJSParams(params), null);
    }

    protected HashMap<String, String> prepareJsStateParameter(Session session) throws Exception {
        String stateToken = loginStateProvider.get();
        session.putValue(Constants.SESSION_LOGIN_STATE, stateToken);
        HashMap<String, String> jsParams = new HashMap<>();
        jsParams.put(Constants.PARAMETER_STATE, stateToken);
        return jsParams;
    }

    protected Response answerWithJSONBody(int statuscode, Map<String, String> params) throws JsonProcessingException {
        return answerWithBody(statuscode, new ObjectMapper().writeValueAsString(params));
    }

    protected Response answerWithBody(int statuscode, String body) {
        return new ResponseBuilder().statuscode(statuscode).body(body).build();
    }

    protected Response okWithJSONBody(Map<String, String> params) throws JsonProcessingException {
        return answerWithJSONBody(200, params);
    }

    protected Response answerWithError(int statusCode, String error) throws JsonProcessingException {
        return answerWithBody(statusCode, getErrorBody(error));

    }

    protected Set<String> getValidClaimsFromToken(Token token) throws IOException {
        ClaimsParameter tokenClaims = new ClaimsParameter(token.getClaims());
        Set<String> claims = serverServices.getSupportedScopes().getClaimsForScope(token.getScope());
        claims.addAll(tokenClaims.getAllUserinfoClaimNames());
        claims = serverServices.getSupportedClaims().getValidClaims(claims);
        return claims;
    }
}
