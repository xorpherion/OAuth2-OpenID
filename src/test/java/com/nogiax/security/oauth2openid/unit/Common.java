package com.nogiax.security.oauth2openid.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class Common {

    public static String getMethodName() {
        return Thread.currentThread().getStackTrace()[2].getMethodName();
    }

    public static <T> T defaultExceptionHandling(Exception e) {
        e.printStackTrace();
        return null;
    }

    public static Exchange testExchangeOn(AuthorizationServer server, Supplier<Exchange> requestSupplier, Consumer<Exchange> resultValidation) throws Exception {
        Exchange exc = requestSupplier.get();
        Exchange result = server.invokeOn(exc);
        resultValidation.accept(result);
        return result;
    }

    public static Exchange createAuthRequest(String responseType, String clientId, String redirectUrl, String scope, String state) throws URISyntaxException {
        Map<String, String> params = Parameters.createParams(
                Constants.PARAMETER_RESPONSE_TYPE, responseType,
                Constants.PARAMETER_CLIENT_ID, clientId,
                Constants.PARAMETER_REDIRECT_URI, redirectUrl,
                Constants.PARAMETER_SCOPE, scope,
                Constants.PARAMETER_STATE, state
        );
        params = Parameters.stripEmptyParams(params);

        return new RequestBuilder().uri(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT + "?" + UriUtil.parametersToQuery(params)).method(Method.GET).buildExchange();
    }

    public static Map<String, String> getBodyParamsFromResponse(Exchange exc) throws IOException {
        return new ObjectMapper().readValue(exc.getResponse().getBody(), Map.class);
    }

    public static Map<String, String> getQueryParamsFromRedirectResponse(Exchange exc) throws URISyntaxException {
        return UriUtil.queryToParameters(new URI(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).getQuery());
    }

    public static Map<String, String> getFragmentParamsFromRedirectResponse(Exchange exc) throws URISyntaxException {
        return UriUtil.queryToParameters(new URI(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).getFragment());
    }

    public static Map<String, String> convertLoginPageParamsToMap(String dest) throws URISyntaxException, IOException {
        URI uri = new URI(dest);
        String params = new String(Base64.getDecoder().decode(uri.getFragment().split(Pattern.quote("="))[1]));
        return new ObjectMapper().readValue(params, Map.class);
    }

    public static Exchange createLoginRequest(String username, String password, String state, String cookie) throws URISyntaxException {
        Map<String, String> params = Parameters.createParams(
                Constants.LOGIN_USERNAME, username,
                Constants.LOGIN_PASSWORD, password,
                Constants.SESSION_LOGIN_STATE, state
        );
        params = Parameters.stripEmptyParams(params);

        return new RequestBuilder().uri(ConstantsTest.SERVER_LOGIN_ENDPOINT).body(UriUtil.parametersToQuery(params)).method(Method.POST).header(Constants.HEADER_COOKIE, cookie).buildExchange();
    }

    public static Exchange createConsentRequest(String consent, String state, String cookie) throws URISyntaxException {
        Map<String, String> params = Parameters.createParams(
                Constants.LOGIN_CONSENT, consent,
                Constants.SESSION_LOGIN_STATE, state
        );
        params = Parameters.stripEmptyParams(params);

        return new RequestBuilder().uri(ConstantsTest.SERVER_CONSENT_ENDPOINT).body(UriUtil.parametersToQuery(params)).method(Method.POST).header(Constants.HEADER_COOKIE, cookie).buildExchange();
    }

    public static URI getResponseLocationHeaderAsUri(Exchange exc) throws URISyntaxException {
        return new URI(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
    }

    public static String extractSessionCookie(Exchange exc) {
        if (exc.getProperties().get("membrane_session_id") != null)
            return "SC_ID=" + String.valueOf(exc.getProperties().get("membrane_session_id")).split(Pattern.quote(";"))[0];
        return exc.getRequest().getHeader().getValue(Constants.HEADER_COOKIE);
    }

    public static Exchange createPostLoginRequest(String cookie) throws URISyntaxException {
        return new RequestBuilder().uri(ConstantsTest.SERVER_AFTER_LOGIN_ENDPOINT).method(Method.POST).header(Constants.HEADER_COOKIE, cookie).buildExchange();
    }
}
