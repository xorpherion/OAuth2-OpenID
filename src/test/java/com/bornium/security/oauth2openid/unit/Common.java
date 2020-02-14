package com.bornium.security.oauth2openid.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.bornium.http.Exchange;
import com.bornium.http.Method;
import com.bornium.http.RequestBuilder;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.endpoints.Parameters;
import com.bornium.security.oauth2openid.token.IdTokenProvider;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class Common {

    static IdTokenProvider idTokenProvider;

    static {
        try {
            idTokenProvider = new IdTokenProvider();
        } catch (JoseException e) {
            e.printStackTrace();
        }
    }

    public static IdTokenProvider getIdTokenProvider() {
        return idTokenProvider;
    }

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
        return createOpenIdAuthRequest(responseType, clientId, redirectUrl, scope, state, null, null, null, null, null, null, null, null);
    }

    public static Exchange createOpenIdAuthRequest(String responseType, String clientId, String redirectUrl, String scope, String state, String responseMode, String nonce, String prompt, String maxAge, String idTokenHint, String loginHint, String authenticationContextClass, String claims) throws URISyntaxException {
        Map<String, String> params = Parameters.createParams(
                Constants.PARAMETER_RESPONSE_TYPE, responseType,
                Constants.PARAMETER_CLIENT_ID, clientId,
                Constants.PARAMETER_REDIRECT_URI, redirectUrl,
                Constants.PARAMETER_SCOPE, scope,
                Constants.PARAMETER_STATE, state,
                Constants.PARAMETER_RESPONSE_MODE, responseMode,
                Constants.PARAMETER_NONCE, nonce,
                Constants.PARAMETER_PROMPT, prompt,
                Constants.PARAMETER_MAX_AGE, maxAge,
                Constants.PARAMETER_ID_TOKEN_HINT, idTokenHint,
                Constants.PARAMETER_LOGIN_HINT, loginHint,
                Constants.PARAMETER_ACR_VALUES, authenticationContextClass,
                Constants.PARAMETER_CLAIMS, claims,
                Constants.PARAMETER_DISPLAY, "349872309482390489272390842075",
                Constants.PARAMETER_UI_LOCALES, "38754385837"
        );
        params = Parameters.stripEmptyParams(params);

        return new RequestBuilder().uri(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT + "?" + UriUtil.parametersToQuery(params)).method(Method.GET).buildExchange();
    }

    public static Exchange createOpenIdAuthRequest(Method method, String responseType, String clientId, String redirectUrl, String scope, String state, String responseMode, String nonce, String prompt, String maxAge, String idTokenHint, String loginHint, String authenticationContextClass, String claims) throws URISyntaxException {
        Map<String, String> params = Parameters.createParams(
                Constants.PARAMETER_RESPONSE_TYPE, responseType,
                Constants.PARAMETER_CLIENT_ID, clientId,
                Constants.PARAMETER_REDIRECT_URI, redirectUrl,
                Constants.PARAMETER_SCOPE, scope,
                Constants.PARAMETER_STATE, state,
                Constants.PARAMETER_RESPONSE_MODE, responseMode,
                Constants.PARAMETER_NONCE, nonce,
                Constants.PARAMETER_PROMPT, prompt,
                Constants.PARAMETER_MAX_AGE, maxAge,
                Constants.PARAMETER_ID_TOKEN_HINT, idTokenHint,
                Constants.PARAMETER_LOGIN_HINT, loginHint,
                Constants.PARAMETER_ACR_VALUES, authenticationContextClass,
                Constants.PARAMETER_CLAIMS, claims,
                Constants.PARAMETER_DISPLAY, "349872309482390489272390842075",
                Constants.PARAMETER_UI_LOCALES, "38754385837"
        );
        params = Parameters.stripEmptyParams(params);
        if (method == Method.GET)
            return new RequestBuilder().uri(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT + "?" + UriUtil.parametersToQuery(params)).method(method).buildExchange();
        if (method == Method.POST)
            return new RequestBuilder().uri(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT).body(UriUtil.parametersToQuery(params)).method(method).buildExchange();
        throw new RuntimeException();
    }

    public static Map<String, String> getBodyParamsFromResponse(Exchange exc) throws IOException {
        return new ObjectMapper().readValue(exc.getResponse().getBody(), Map.class);
    }

    private static Map<String, String> getQueryParamsFromRedirectResponse(Exchange exc) throws URISyntaxException {
        return UriUtil.queryToParameters(new URI(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).getQuery());
    }

    private static Map<String, String> getFragmentParamsFromRedirectResponse(Exchange exc) throws URISyntaxException {
        return UriUtil.queryToParameters(new URI(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).getFragment());
    }

    public static Map<String, String> getParamsFromRedirectResponse(Exchange exc, boolean useFragment) throws URISyntaxException {
        if (useFragment)
            return getFragmentParamsFromRedirectResponse(exc);
        return getQueryParamsFromRedirectResponse(exc);
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

    public static Exchange preStepAndTokenRequest(Supplier<Exchange> preStep, String grantType, String redirectUri, String scope, String clientId, String clientSecret, String username, String password) throws Exception {
        return preStepAndTokenRequest(preStep, grantType, redirectUri, scope, clientId, clientSecret, username, password, false);
    }

    public static Exchange preStepAndTokenRequest(Supplier<Exchange> preStep, String grantType, String redirectUri, String scope, String clientId, String clientSecret, String username, String password, boolean useFragment) throws Exception {
        String cookie = null;
        String code = null;
        if (preStep != null) {
            Exchange exc = preStep.get();
            cookie = extractSessionCookie(exc);
            code = Common.getParamsFromRedirectResponse(exc, useFragment).get(Constants.PARAMETER_CODE);
            if (code == null)
                code = Common.getParamsFromRedirectResponse(exc, !useFragment).get(Constants.PARAMETER_CODE);
        }


        Map<String, String> params = createBodyParams(grantType, code, redirectUri, scope, username, password);

        if (clientSecret == null)
            return addCookieIfNotNull(new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)), useFragment ? null : cookie).buildExchange();
        String authHeader = Util.encodeToBasicAuthValue(clientId, clientSecret);
        return addCookieIfNotNull(new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_AUTHORIZATION, authHeader), useFragment ? null : cookie).buildExchange();
    }

    private static RequestBuilder addCookieIfNotNull(RequestBuilder response, String cookie) {
        if (cookie != null)
            response.header(Constants.HEADER_COOKIE, cookie);
        return response;
    }

    private static Map<String, String> createBodyParams(String grantType, String code, String redirectUri, String scope, String username, String password) {
        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_GRANT_TYPE, grantType);
        params.put(Constants.PARAMETER_CODE, code);
        params.put(Constants.PARAMETER_REDIRECT_URI, redirectUri);
        params.put(Constants.PARAMETER_SCOPE, scope);
        params.put(Constants.PARAMETER_USERNAME, username);
        params.put(Constants.PARAMETER_PASSWORD, password);

        return Parameters.stripEmptyParams(params);
    }

    public static Exchange preStepAndRefreshTokenRequest(Supplier<Exchange> preStep, String scope, String clientId, String clientSecret) throws IOException, URISyntaxException {
        return preStepAndRefreshTokenRequest(preStep.get(), scope, clientId, clientSecret);
    }

    public static Exchange preStepAndRefreshTokenRequest(Exchange preStep, String scope, String clientId, String clientSecret) throws IOException, URISyntaxException {

        Exchange exc = preStep;
        String cookie = extractSessionCookie(exc);
        String refreshToken = String.valueOf(new ObjectMapper().readValue(exc.getResponse().getBody(), Map.class).get(Constants.PARAMETER_REFRESH_TOKEN));

        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_GRANT_TYPE, Constants.PARAMETER_VALUE_REFRESH_TOKEN);
        params.put(Constants.PARAMETER_REFRESH_TOKEN, refreshToken);
        if (scope != null)
            params.put(Constants.PARAMETER_SCOPE, scope);

        params = Parameters.stripEmptyParams(params);

        if (clientSecret == null)
            return addCookieIfNotNull(new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)), cookie).buildExchange();
        String authHeader = Util.encodeToBasicAuthValue(clientId, clientSecret);
        return addCookieIfNotNull(new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_AUTHORIZATION, authHeader), cookie).buildExchange();
    }

    public static Exchange createUserinfoRequest(String accessToken, String tokenType) throws URISyntaxException {
        String authHeader = "";
        if (tokenType != null)
            authHeader += tokenType + " ";
        if (accessToken != null)
            authHeader += accessToken;
        return new RequestBuilder().uri(ConstantsTest.SERVER_USERINFO_ENDPOINT).method(Method.GET).header(Constants.HEADER_AUTHORIZATION, authHeader).buildExchange();
    }

    public static Exchange createRevocationRequest(String accessToken, String clientId, String clientSecret) throws UnsupportedEncodingException, URISyntaxException {
        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_TOKEN, accessToken);
        params = Parameters.stripEmptyParams(params);

        if (clientSecret == null)
            return new RequestBuilder().uri(ConstantsTest.SERVER_REVOCATION_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).buildExchange();
        String authHeader = Util.encodeToBasicAuthValue(clientId, clientSecret);
        return new RequestBuilder().uri(ConstantsTest.SERVER_REVOCATION_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_AUTHORIZATION, authHeader).buildExchange();

    }
}
