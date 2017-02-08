package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.*;
import com.nogiax.security.oauth2openid.token.Token;

import java.util.Map;

/**
 * Created by Xorpherion on 07.02.2017.
 */
public class RevocationEndpoint extends Endpoint {
    public RevocationEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_REVOCATION);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        Map<String,String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
        params = Parameters.stripEmptyParams(params);

        if(params.get(Constants.PARAMETER_TOKEN) == null){
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        Token token = serverServices.getTokenManager().findToken(params.get(Constants.PARAMETER_TOKEN));
        if(token == null){
            exc.setResponse(new ResponseBuilder().statuscode(200).build());
            return;
        }

        boolean clientIsAuthorized = false;
        String clientId = null;
        if(serverServices.getProvidedServices().getClientDataProvider().isConfidential(token.getClientId())){
            if (exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION) != null) {
                try {
                    User clientData = Util.decodeFromBasicAuthValue(exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION));
                    clientIsAuthorized = serverServices.getProvidedServices().getClientDataProvider().verify(clientData.getName(), clientData.getPassword());
                    if (clientIsAuthorized)
                        clientId = clientData.getName();
                } catch (Exception e) {
                    clientIsAuthorized = false;
                    clientId = null;
                }
            }
        }




        if (clientId == null)
            clientId = token.getClientId();

        if (!clientIsAuthorized && serverServices.getProvidedServices().getClientDataProvider().isConfidential(clientId)) {
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }

        if(!clientId.equals(token.getClientId())){
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        // valid request

        token.revokeCascade();

        exc.setResponse(new ResponseBuilder().statuscode(200).build());
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
