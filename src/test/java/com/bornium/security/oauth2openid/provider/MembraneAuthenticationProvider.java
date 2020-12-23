package com.bornium.security.oauth2openid.provider;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.UriUtil;
import com.bornium.impl.BearerTokenProvider;
import com.bornium.impl.LoginEndpoint;
import com.bornium.impl.LoginResultWithCallback;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.AuthenticationProvider;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.GrantContextProvider;
import com.bornium.security.oauth2openid.providers.LoginResult;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.server.TokenContext;
import com.bornium.security.oauth2openid.server.endpoints.Parameters;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jose4j.base64url.Base64;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class MembraneAuthenticationProvider implements AuthenticationProvider {

    private final BearerTokenProvider loginStateProvider;

    public MembraneAuthenticationProvider() {
        loginStateProvider = new BearerTokenProvider();
    }


    @Override
    public void initiateAuthenticationAndConsent(String ctxId, boolean skipConsentCheck, Exchange currentlyRunningExchange, AuthorizationServer server, Consumer<LoginResult> callback) {
        try {
            GrantContext ctx = server.getProvidedServices().getGrantContextProvider().findById(ctxId).get();

            HashMap<String, String> params = prepareJsStateParameter(ctx, server.getProvidedServices().getContextPath());
            params.put(Constants.GRANT_CONTEXT_ID, ctx.getIdentifier());
            params.entrySet().stream().forEach(e -> {
                try {
                    ctx.putValue(e.getKey(),e.getValue());
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            server.getProvidedServices().getGrantContextProvider().persist(ctx);
            ((LoginEndpoint)server.getLoginEndpoint()).getCtxToAuthenticatedUser().put(ctx.getIdentifier(), new LoginResultWithCallback(ctx.getIdentifier(), skipConsentCheck,null,callback));
            currentlyRunningExchange.setResponse(redirectToLogin(params, server.getProvidedServices().getContextPath()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected HashMap<String, String> prepareJsStateParameter(GrantContext ctx, String contextPath) throws Exception {
        String stateToken = loginStateProvider.get(new TokenContext(null));
        ctx.putValue(Constants.SESSION_LOGIN_STATE, stateToken);
        HashMap<String, String> jsParams = new HashMap<>();
        jsParams.put(Constants.PARAMETER_STATE, ctx.getValue(Constants.PARAMETER_STATE));
        jsParams.put(Constants.SESSION_LOGIN_STATE, stateToken);
        jsParams.put(Constants.CONTEXT_PATH,contextPath);
        return jsParams;
    }

    protected Response redirectToLogin(Map<String, String> params, String contextPath) throws UnsupportedEncodingException, JsonProcessingException {
        return redirectToUrl(contextPath + Constants.ENDPOINT_LOGIN + "#params=" + prepareJSParams(params), null);
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

    protected String prepareJSParams(Map<String, String> params) throws JsonProcessingException, UnsupportedEncodingException {
        String json = new ObjectMapper().writeValueAsString(params);
        return UriUtil.encode(Base64.encode(json.getBytes()));
    }
}
