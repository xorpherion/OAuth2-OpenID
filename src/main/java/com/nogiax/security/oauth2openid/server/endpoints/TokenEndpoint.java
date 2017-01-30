package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.*;
import com.nogiax.security.oauth2openid.token.Token;
import com.nogiax.security.oauth2openid.tokenanswers.CombinedResponseGenerator;

import java.util.Map;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class TokenEndpoint extends Endpoint {
    public TokenEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_TOKEN);
    }

    @Override
    public void invokeOnOAuth2(Exchange exc) throws Exception {
        log.info("Token endpoint");

        boolean clientIsAuthorized = false;
        String clientId = null;
        if(exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION) != null) {
            try {
                User clientData = Util.decodeFromBasicAuthValue(exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION));
                clientIsAuthorized = serverServices.getProvidedServices().getClientDataProvider().verify(clientData.getName(),clientData.getPassword());
                if(clientIsAuthorized)
                    clientId = clientData.getName();
            }catch (Exception e){
            }
        }

        Map<String,String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
        String code = params.get(Constants.PARAMETER_CODE);
        if(clientId == null)
            clientId = params.get(Constants.PARAMETER_CLIENT_ID);

        if(!serverServices.getTokenManager().getAuthorizationCodes().tokenExists(code)){

        }

        Token authorizationCodeToken = serverServices.getTokenManager().getAuthorizationCodes().getToken(code);

        if(authorizationCodeToken.isExpired()){

        }

        if(!authorizationCodeToken.getClientId().equals(clientId)){

        }

        String redirectUri = serverServices.getProvidedServices().getClientDataProvider().getRedirectUri(clientId);
        if(!redirectUri.equals(params.get(Constants.PARAMETER_REDIRECT_URI))){

        }

        // request is now valid

        log.info("Valid Token Request");

        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        session.putValue(Constants.SESSION_AUTHORIZATION_CODE,code);
        String response = Constants.TOKEN_TYPE_TOKEN;
        if(hasOpenIdScope(exc))
            response += "_" + Constants.TOKEN_TYPE_ID_TOKEN;

        Map<String, String> responseBody = new CombinedResponseGenerator(serverServices, exc).invokeResponse(response);
        exc.setResponse(okWithJSONBody(responseBody));
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
