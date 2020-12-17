package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.permissions.ClaimsParameter;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.TokenContext;
import com.bornium.impl.BearerTokenProvider;
import com.bornium.security.oauth2openid.token.Token;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jose4j.base64url.Base64;
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

    protected final AuthorizationServer serverServices;
    String[] paths;
    BearerTokenProvider loginStateProvider;

    public Endpoint(AuthorizationServer serverServices, String... paths) {
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
        return redirectToCallbackWithError(callbackUrl, error, state, false);
    }

    protected Response redirectToCallbackWithError(String callbackUrl, String error, String state, boolean useFragment) {
        HashMap<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_ERROR, error);
        return redirectToCallbackWithParams(callbackUrl, params, state, useFragment);
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
        return redirectToUrl(serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_LOGIN + "#params=" + prepareJSParams(params), null);
    }

    protected String prepareJSParams(Map<String, String> params) throws JsonProcessingException, UnsupportedEncodingException {
        String json = new ObjectMapper().writeValueAsString(params);
        return UriUtil.encode(Base64.encode(json.getBytes()));
    }

    protected boolean isLoggedIn(GrantContext ctx) throws Exception {
        String loggedIn = ctx.getValue(Constants.SESSION_LOGGED_IN);
        return Constants.VALUE_YES.equals(loggedIn);
    }

    protected boolean hasGivenConsent(GrantContext ctx) throws Exception {
        String consentGiven = ctx.getValue(Constants.SESSION_CONSENT_GIVEN);
        return Constants.VALUE_YES.equals(consentGiven);
    }

    protected boolean isLoggedInAndHasGivenConsent(GrantContext ctx) throws Exception {
        return isLoggedIn(ctx) && hasGivenConsent(ctx);
    }

    protected Response redirectToConsent(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_CONSENT + "#params=" + prepareJSParams(params), null);
    }

    protected Response redirectToDeviceVerification(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_VERIFICATION + "#params=" + prepareJSParams(params), null);
    }

    protected HashMap<String, String> prepareJsStateParameter(GrantContext session) throws Exception {
        String stateToken = loginStateProvider.get(new TokenContext(null));
        session.putValue(Constants.SESSION_LOGIN_STATE, stateToken);
        HashMap<String, String> jsParams = new HashMap<>();
        jsParams.put(Constants.PARAMETER_STATE, stateToken);
        jsParams.put(Constants.CONTEXT_PATH,this.serverServices.getProvidedServices().getContextPath());
        return jsParams;
    }

    protected Response answerWithJSONBody(int statuscode, Map<String, Object> params) throws JsonProcessingException {
        return answerWithBody(statuscode, new ObjectMapper().writeValueAsString(params), Constants.HEADER_VALUE_CONTENT_TYPE_JSON);
    }

    protected Response answerWithBody(int statuscode, String body, String contentType) {
        return new ResponseBuilder().statuscode(statuscode).body(body).header(Constants.HEADER_CONTENT_TYPE,contentType).build();
    }

    protected Response okWithJSONBody(Map params) throws JsonProcessingException {
        return answerWithJSONBody(200, params);
    }

    protected Response answerWithError(int statusCode, String error) throws JsonProcessingException {
        return answerWithBody(statusCode, getErrorBody(error), "application/json");

    }

    protected Set<String> getValidUserinfoClaimsFromToken(Token token) throws IOException {
        ClaimsParameter tokenClaims = new ClaimsParameter(token.getClaims());
        Set<String> claims = serverServices.getSupportedScopes().getClaimsForScope(token.getScope());
        claims.addAll(tokenClaims.getAllUserinfoClaimNames());
        claims = serverServices.getSupportedClaims().getValidClaims(claims);
        return claims;
    }

    protected Set<String> getValidIdTokenClaimsFromToken(Token token) throws IOException {
        ClaimsParameter tokenClaims = new ClaimsParameter(token.getClaims());
        Set<String> claims = serverServices.getSupportedScopes().getClaimsForScope(token.getScope());
        claims.addAll(tokenClaims.getAllIdTokenClaimNames());
        claims = serverServices.getSupportedClaims().getValidClaims(claims);
        return claims;
    }

    protected boolean setToResponseModeOrUseDefault(Exchange exc, GrantContext session) throws Exception {
        String responseType = session.getValue(Constants.PARAMETER_RESPONSE_TYPE);
        if (responseType == null)
            throw new RuntimeException();
        return setToResponseModeOrUseDefault(exc, session, responseType.contains(Constants.PARAMETER_VALUE_TOKEN));
    }

    protected boolean setToResponseModeOrUseDefault(Exchange exc, GrantContext session, boolean defaultValue) throws Exception {
        if (hasOpenIdScope(exc))
            if (session.getValue(Constants.PARAMETER_RESPONSE_MODE) != null) {
                String responseMode = session.getValue(Constants.PARAMETER_RESPONSE_MODE);
                if (responseMode.equals(Constants.PARAMETER_VALUE_QUERY))
                    return false;
                if (responseMode.equals(Constants.PARAMETER_VALUE_FRAGMENT))
                    return true;
            }
        return defaultValue;
    }

    protected Map<String, String> getParams(Exchange exc) {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getRawQuery());
        if (params.isEmpty())
            params = UriUtil.queryToParameters(exc.getRequest().getBody());
        params = Parameters.stripEmptyParams(params);
        return params;
    }

}
