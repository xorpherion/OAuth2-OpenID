package com.nogiax.security.oauth2openid.client;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nogiax.http.Exchange;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.ClientProvider;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;
import com.nogiax.security.oauth2openid.token.BearerTokenProvider;
import com.sun.jndi.toolkit.url.Uri;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        Exchange result = invokeWhenCallback(exc);
        if (result == null)
            result = invokeAuthRedirect(exc);
        if(result != null && exc != null)
            if(!exc.getProperties().isEmpty())
                result.setProperties(exc.getProperties());
        return result;
    }

    private Exchange invokeAuthRedirect(Exchange exc) throws Exception {
        log.info("Client auth redirect");
        return createAuthorizationEndpointRedirectForResourceOwner(exc);
    }

    private Exchange invokeWhenCallback(Exchange exc) throws Exception {
        if (!clientData.getRedirectUri().endsWith(exc.getRequest().getUri().getPath()))
            return null;
        // callback impl
        log.info("Client callback");

        Map<String,String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());

        Session session = clientProvider.getSessionProvider().getSession(exc);
        String state = session.getValue(Constants.PARAMETER_STATE);

        if(!state.equals(params.get(Constants.PARAMETER_STATE))){
            return new ResponseBuilder().statuscode(400).body(Constants.ERROR_POSSIBLE_CSRF).buildExchange();
        }



        return new ResponseBuilder().statuscode(200).body("We did it!").buildExchange();
    }

    public Exchange createAuthorizationEndpointRedirectForResourceOwner(Exchange exc) throws Exception {
        return new ResponseBuilder()
                .redirectTempWithGet(getAuthorizationEndpointUriWithQuery(exc)).buildExchange();
    }

    private String getAuthorizationEndpointUriWithQuery(Exchange exc) throws Exception {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(Constants.PARAMETER_RESPONSE_TYPE, Constants.GRANT_CODE);
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
        session.putValue(Constants.PARAMETER_STATE,state);

        return state;
    }
}
