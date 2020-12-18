package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.token.Token;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class WrappedEndpoint<T extends Endpoint> extends Endpoint{

    protected T toBeWrapped;

    public WrappedEndpoint(T toBeWrapped) {
        super(null, null);
        this.toBeWrapped = toBeWrapped;
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        toBeWrapped.invokeOn(exc);
    }

    @Override
    public void useIfResponsible(Exchange exc) throws Exception {
        toBeWrapped.useIfResponsible(exc);
    }

    @Override
    public boolean isResponsible(Exchange exc) {
        return toBeWrapped.isResponsible(exc);
    }

    @Override
    protected boolean hasOpenIdScope(String scope) {
        return toBeWrapped.hasOpenIdScope(scope);
    }

    @Override
    protected boolean hasOpenIdScope(GrantContext ctx) throws Exception {
        return toBeWrapped.hasOpenIdScope(ctx);
    }

    @Override
    protected Response informResourceOwnerError(String error) throws JsonProcessingException {
        return toBeWrapped.informResourceOwnerError(error);
    }

    @Override
    protected boolean clientExists(String clientId) {
        return toBeWrapped.clientExists(clientId);
    }

    @Override
    protected Response redirectToCallbackWithError(String callbackUrl, String error, String state) {
        return toBeWrapped.redirectToCallbackWithError(callbackUrl, error, state);
    }

    @Override
    protected Response redirectToCallbackWithError(String callbackUrl, String error, String state, boolean useFragment) {
        return toBeWrapped.redirectToCallbackWithError(callbackUrl, error, state, useFragment);
    }

    @Override
    protected Response redirectToCallbackWithParams(String callbackurl, Map<String, String> params, String state) {
        return toBeWrapped.redirectToCallbackWithParams(callbackurl, params, state);
    }

    @Override
    protected Response redirectToCallbackWithParams(String callbackurl, Map<String, String> params, String state, boolean useFragment) {
        return toBeWrapped.redirectToCallbackWithParams(callbackurl, params, state, useFragment);
    }

    @Override
    protected Response redirectToUrl(String url, Map<String, String> params) {
        return toBeWrapped.redirectToUrl(url, params);
    }

    @Override
    protected Response redirectToUrl(String url, Map<String, String> params, boolean useFragment) {
        return toBeWrapped.redirectToUrl(url, params, useFragment);
    }

    @Override
    protected Response redirectToLogin(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return toBeWrapped.redirectToLogin(params);
    }

    @Override
    protected String prepareJSParams(Map<String, String> params) throws JsonProcessingException, UnsupportedEncodingException {
        return toBeWrapped.prepareJSParams(params);
    }

    @Override
    protected boolean isLoggedIn(Session session) throws Exception {
        return toBeWrapped.isLoggedIn(session);
    }

    @Override
    protected boolean hasGivenConsent(Session session) throws Exception {
        return toBeWrapped.hasGivenConsent(session);
    }

    @Override
    protected boolean isLoggedInAndHasGivenConsent(Session session) throws Exception {
        return toBeWrapped.isLoggedInAndHasGivenConsent(session);
    }

    @Override
    protected Response redirectToConsent(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return toBeWrapped.redirectToConsent(params);
    }

    @Override
    protected Response redirectToDeviceVerification(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return toBeWrapped.redirectToDeviceVerification(params);
    }

    @Override
    protected HashMap<String, String> prepareJsStateParameter(GrantContext session) throws Exception {
        return toBeWrapped.prepareJsStateParameter(session);
    }

    @Override
    protected Response answerWithJSONBody(int statuscode, Map<String, Object> params) throws JsonProcessingException {
        return toBeWrapped.answerWithJSONBody(statuscode, params);
    }

    @Override
    protected Response answerWithBody(int statuscode, String body, String contentType) {
        return toBeWrapped.answerWithBody(statuscode, body, contentType);
    }

    @Override
    protected Response okWithJSONBody(Map params) throws JsonProcessingException {
        return toBeWrapped.okWithJSONBody(params);
    }

    @Override
    protected Response answerWithError(int statusCode, String error) throws JsonProcessingException {
        return toBeWrapped.answerWithError(statusCode, error);
    }

    @Override
    protected Set<String> getValidUserinfoClaimsFromToken(Token token) throws IOException {
        return toBeWrapped.getValidUserinfoClaimsFromToken(token);
    }

    @Override
    protected Set<String> getValidIdTokenClaimsFromToken(Token token) throws IOException {
        return toBeWrapped.getValidIdTokenClaimsFromToken(token);
    }

    @Override
    protected boolean setToResponseModeOrUseDefault(GrantContext ctx) throws Exception {
        return toBeWrapped.setToResponseModeOrUseDefault(ctx);
    }

    @Override
    protected boolean setToResponseModeOrUseDefault(GrantContext ctx, boolean defaultValue) throws Exception {
        return toBeWrapped.setToResponseModeOrUseDefault(ctx, defaultValue);
    }

    @Override
    protected Map<String, String> getParams(Exchange exc) {
        return toBeWrapped.getParams(exc);
    }
}
