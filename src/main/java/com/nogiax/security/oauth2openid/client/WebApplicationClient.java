package com.nogiax.security.oauth2openid.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.ClientProvider;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.token.BearerTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class WebApplicationClient {
    Logger log = LoggerFactory.getLogger(WebApplicationClient.class);

    private final ClientProvider clientProvider;
    private final OAuth2ClientData clientData;
    private final OAuth2AuthorizationServerData serverData;

    private Cache<String, Exchange> originalRequestsForState;
    private BearerTokenProvider stateTokenProvider;

    public WebApplicationClient(ClientProvider clientProvider, OAuth2ClientData clientData, OAuth2AuthorizationServerData serverData) {
        this.clientProvider = clientProvider;
        this.clientData = clientData;
        this.serverData = serverData;

        originalRequestsForState = CacheBuilder.newBuilder().expireAfterAccess(10, TimeUnit.MINUTES).build();
        stateTokenProvider = new BearerTokenProvider();
    }

    public Exchange invokeOn(Exchange exc) throws Exception {
        log.info("Client connect");
        Exchange result;
        Session session = clientProvider.getSessionProvider().getSession(exc);
        if (session != null && session.getValue(Constants.SESSION_LOGGED_IN) != null && session.getValue(Constants.SESSION_LOGGED_IN).equals(Constants.VALUE_YES)) {
            exc.getRequest().getHeader().append(Constants.HEADER_AUTHORIZATION, session.getValue(Constants.PARAMETER_TOKEN_TYPE) + " " + session.getValue(Constants.PARAMETER_ACCESS_TOKEN));
            return exc;
        }

        if (isCallbackCall(exc))
            result = invokeWhenCallback(exc);
        else
            result = invokeAuthRedirect(exc);
        if (result.getRequest() == null)
            result.setRequest(exc.getRequest());
        if (exc != null)
            if (!exc.getProperties().isEmpty())
                result.setProperties(exc.getProperties());
        return result;
    }

    private Exchange invokeAuthRedirect(Exchange exc) throws Exception {
        log.info("Client auth redirect");
        return createAuthorizationEndpointRedirectForResourceOwner(exc);
    }

    private Exchange invokeWhenCallback(Exchange exc) throws Exception {
        // callback impl
        log.info("Client callback");

        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());

        Session session = clientProvider.getSessionProvider().getSession(exc);
        String state = session.getValue(Constants.PARAMETER_STATE);

        if (!state.equals(params.get(Constants.PARAMETER_STATE))) {
            return new ResponseBuilder().statuscode(400).body(Constants.ERROR_POSSIBLE_CSRF).buildExchange();
        }


        Exchange accessTokenRequest = createAccessTokenRequest(exc, params.get(Constants.PARAMETER_CODE));
        Exchange accessTokenResponse = clientProvider.getHttpClient().sendExchange(accessTokenRequest);

        Map<String, Object> json = new ObjectMapper().readValue(accessTokenResponse.getResponse().getBody(), Map.class);

        for (String s : json.keySet())
            session.putValue(s, json.get(s).toString());
        session.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);

        Exchange origExc = originalRequestsForState.getIfPresent(params.get(Constants.PARAMETER_STATE));
        exc.setRequest(origExc.getRequest());
        exc.getRequest().getHeader().append(Constants.HEADER_AUTHORIZATION, session.getValue(Constants.PARAMETER_TOKEN_TYPE) + " " + session.getValue(Constants.PARAMETER_ACCESS_TOKEN));
        return exc;
    }

    private Exchange createAccessTokenRequest(Exchange exc, String authorizationCode) throws URISyntaxException, UnsupportedEncodingException {
        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_GRANT_TYPE, Constants.PARAMETER_VALUE_AUTHORIZATION_CODE);
        params.put(Constants.PARAMETER_CODE, authorizationCode);
        params.put(Constants.PARAMETER_REDIRECT_URI, clientData.getRedirectUri());
        params.put(Constants.PARAMETER_SCOPE, clientData.getScope());

        return new RequestBuilder()
                .method(Method.POST)
                .uri(serverData.getTokenEndpoint())
                .body(UriUtil.parametersToQuery(params))
                .header(Constants.HEADER_AUTHORIZATION, getBasicAuthValue())
                .header(Constants.HEADER_COOKIE, exc.getRequest().getHeader().getValue(Constants.HEADER_COOKIE))
                .buildExchange();
    }

    private String getBasicAuthValue() throws UnsupportedEncodingException {
        return Util.encodeToBasicAuthValue(clientData.getClientId(), clientData.getClientSecret());
    }

    private boolean isCallbackCall(Exchange exc) {
        return clientData.getRedirectUri().endsWith(exc.getRequest().getUri().getPath());
    }

    public Exchange createAuthorizationEndpointRedirectForResourceOwner(Exchange exc) throws Exception {
        return new ResponseBuilder()
                .redirectTempWithGet(getAuthorizationEndpointUriWithQuery(exc)).buildExchange();
    }

    private String getAuthorizationEndpointUriWithQuery(Exchange exc) throws Exception {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(Constants.PARAMETER_RESPONSE_TYPE, Constants.PARAMETER_VALUE_CODE);
        parameters.put(Constants.PARAMETER_CLIENT_ID, clientData.getClientId());
        parameters.put(Constants.PARAMETER_REDIRECT_URI, clientData.getRedirectUri());
        parameters.put(Constants.PARAMETER_SCOPE, clientData.getScope());
        parameters.put(Constants.PARAMETER_STATE, createStateAndSaveOriginalRequestToIt(exc));

        return serverData.getAuthEndpoint() + "?" + UriUtil.parametersToQuery(parameters);
    }

    private String createStateAndSaveOriginalRequestToIt(Exchange exc) throws Exception {
        String state = stateTokenProvider.get();
        originalRequestsForState.put(state, exc);

        Session session = clientProvider.getSessionProvider().getSession(exc);
        session.putValue(Constants.PARAMETER_STATE, state);

        return state;
    }
}
