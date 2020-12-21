package com.bornium.impl;

import com.bornium.http.Exchange;
import com.bornium.http.Method;
import com.bornium.http.Response;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.BodyUtil;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.endpoints.Endpoint;
import com.bornium.security.oauth2openid.token.CombinedTokenManager;
import com.bornium.security.oauth2openid.token.Token;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

public class VerificationEndpoint extends Endpoint {
    public VerificationEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_VERIFICATION);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        CombinedTokenManager tokenManager = serverServices.getTokenManager();

        if (exc.getRequest().getMethod() == Method.GET) {
            Map<String, String> params = getParams(exc);

            String userCode = params.get(Constants.PARAMETER_USER_CODE);
            GrantContext ctx = getContextFromUserCodeOrGrantContextIdOrDefault(params, userCode);

            if(ctx.getIdentifier() == null)
                ctx.setIdentifier(loginStateProvider.get(null));



            if (requireLogin(exc,session, ctx, userCode))
                return;

            if (userCode == null) {
                userCode = ctx.getValue(Constants.PARAMETER_USER_CODE);
                if (userCode != null)
                    ctx.removeValue(Constants.PARAMETER_USER_CODE);
            }

            if (userCode != null) {
                exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, null, null)));
                return;
            }

            // here we are in the /verify#{usercode=} or /verify#{usercode=abc} case

            exc.setResponse(sendUsercodepage());
            return;

        }

        Map<String, String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());

        String userCode = params.get("user_code");
        GrantContext ctx = getContextFromUserCodeOrGrantContextIdOrDefault(params, userCode);

        if (userCode != null)
            userCode = UriUtil.decode(userCode);

        if (requireLogin(exc, session,ctx, userCode))
            return;

        Token userToken = tokenManager.getUserCodes().getToken(userCode);
        if (userToken == null) {
            exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, null, Constants.ERROR_INVALID_REQUEST)));
            return;
        }

        if (userToken.isExpired()) {
            exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, null, Constants.ERROR_INVALID_GRANT)));
            return;
        }

        if (userToken.isManuallyRevoked()) {
            exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, null, Constants.ERROR_INVALID_GRANT)));
            return;
        }

        if (userToken.getUsages() > 0) {
            exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, null, Constants.ERROR_INVALID_GRANT)));
            return;
        }

        String consent = params.get("consent");
        if (consent == null || !consent.equals("yes")) {
            if (consent != null)
                userToken.revokeCascade();

            HashMap<String, String> jsParams = prepareJsStateParameter(ctx);
            if (userCode != null)
                jsParams.put(Constants.PARAMETER_USER_CODE, userCode);
            exc.setResponse(redirectToSelf(jsParams));
            return;
        }

        String scope = params.get("scope");
        if (scope != null)
            scope = UriUtil.decode(scope);
        if (scope == null || !userToken.getScope().equals(scope)) {
            exc.setResponse(redirectToSelf(prepareJsStateParameter(userCode, userToken.getScope(), null)));
            return;
        }

        Token deviceToken = tokenManager.getDeviceCodes().getToken("pre:" + userToken.getUsername());
        String deviceCode = deviceToken.getValue().replaceFirst("^pre:", "");
        
        String username = ctx.getValue(Constants.LOGIN_USERNAME);
        String clientId = deviceToken.getClientId();

        tokenManager.addTokenToManager(tokenManager.getDeviceCodes(),
                tokenManager.createDeviceTokenWithDefaultDuration(deviceCode, username, clientId, scope));

        userToken.incrementUsage();
        deviceToken.incrementUsage();

        exc.setResponse(sendSuccesspage());
        serverServices.getProvidedServices().getGrantContextProvider().invalidationHint(ctx.getIdentifier());

        ctx.removeValue(Constants.PARAMETER_USER_CODE);
    }

    private GrantContext getContextFromUserCodeOrGrantContextIdOrDefault(Map<String, String> params, String userCode) {
        return serverServices.getProvidedServices().getGrantContextProvider().findById(userCode)
                .orElseGet(() -> serverServices.getProvidedServices().getGrantContextProvider().findByIdOrCreate(params.get(Constants.GRANT_CONTEXT_ID)));
    }

    private boolean requireLogin(Exchange exc, Session session, GrantContext ctx, String userCode) throws Exception {
        if (isLoggedIn(session))
            return false;

        ctx.putValue(Constants.PARAMETER_USER_CODE, userCode == null ? "" : userCode);

        HashMap<String, String> jsParams = prepareJsStateParameter(ctx);
        jsParams.put(Constants.GRANT_CONTEXT_ID, ctx.getIdentifier());
        serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
        exc.setResponse(redirectToLogin(jsParams));
        return true;
    }

    protected HashMap<String, String> prepareJsStateParameter(String userCode, String scope, String error) throws Exception {
        HashMap<String, String> jsParams = new HashMap<>();
        if (userCode != null)
            jsParams.put(Constants.PARAMETER_USER_CODE, userCode);
        if (scope != null)
            jsParams.put(Constants.PARAMETER_SCOPE, scope);
        if (error != null)
            jsParams.put(Constants.PARAMETER_ERROR, error);
        jsParams.put(Constants.CONTEXT_PATH,this.serverServices.getProvidedServices().getContextPath());
        return jsParams;
    }


    private Response sendUsercodepage() throws IOException {
        return new ResponseBuilder().statuscode(200).header("Content-Type", "text/html").body(loadUsercodepage()).build();
    }

    private Response sendSuccesspage() throws IOException {
        return new ResponseBuilder().statuscode(200).header("Content-Type", "text/html").body(loadSuccesspage()).build();
    }

    private String loadUsercodepage() throws IOException {
        return loadPage("usercode.html");
    }

    private String loadSuccesspage() throws IOException {
        return loadPage("success.html");
    }

    private String loadPage(String page) throws IOException {
        return CharStreams.toString(new InputStreamReader(this.getClass().getResourceAsStream("/static/deviceverification/" + page), Charsets.UTF_8));
    }

    protected Response redirectToSelf(Map<String, String> params) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(serverServices.getProvidedServices().getContextPath() + Constants.ENDPOINT_VERIFICATION + "#params=" + prepareJSParams(params), null);
    }
}
