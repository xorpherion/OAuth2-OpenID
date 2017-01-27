package com.nogiax.security.oauth2openid.client;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nogiax.http.Exchange;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.ClientProvider;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.token.BearerTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
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

    public Exchange invokeOn(Exchange exc) {
        log.info("Client connect");
        Exchange result = invokeWhenCallback(exc);
        if (result == null)
            result = invokeAuthRedirect(exc);
        return result;
    }

    private Exchange invokeAuthRedirect(Exchange exc) {
        log.info("Client auth redirect");
        return createAuthorizationEndpointRedirectForResourceOwner(exc);
    }

    private Exchange invokeWhenCallback(Exchange exc) {
        if (!clientData.getRedirectUri().endsWith(exc.getRequest().getUri().getPath()))
            return null;
        // callback impl
        log.info("Client callback");

        return new Exchange();
    }

    public Exchange createAuthorizationEndpointRedirectForResourceOwner(Exchange exc) {
        return new ResponseBuilder()
                .redirectTemp(getAuthorizationEndpointUriWithQuery(exc)).buildExchange();
    }

    private String getAuthorizationEndpointUriWithQuery(Exchange exc) {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(Constants.PARAMETER_RESPONSE_TYPE, Constants.OAUTH2_GRANT_CODE);
        parameters.put(Constants.PARAMETER_CLIENT_ID, clientData.getClientId());
        parameters.put(Constants.PARAMETER_REDIRECT_URI, clientData.getRedirectUri());
        parameters.put(Constants.PARAMETER_SCOPE, clientData.getScope());
        parameters.put(Constants.PARAMETER_STATE, createStateAndSaveOriginalRequestToIt(exc));

        return serverData.getAuthEndpoint() + "?" + UriUtil.parametersToQuery(parameters);
    }

    private String createStateAndSaveOriginalRequestToIt(Exchange exc) {
        String state = stateTokenProvider.get();
        originalRequestsForState.put(state, exc);
        return state;
    }
}
