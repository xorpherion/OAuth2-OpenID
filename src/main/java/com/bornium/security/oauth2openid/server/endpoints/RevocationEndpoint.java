package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.User;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.token.Token;

import java.util.Map;

/**
 * Created by Xorpherion on 07.02.2017.
 */
public class RevocationEndpoint extends Endpoint {
    public RevocationEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_REVOCATION);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
        params = Parameters.stripEmptyParams(params);

        if (params.get(Constants.PARAMETER_TOKEN) == null) {
            log.debug("Parameter 'token' is missing.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        Token token = serverServices.getTokenManager().findToken(params.get(Constants.PARAMETER_TOKEN));
        if (token == null) {
            log.debug("Token ('" + params.get(Constants.PARAMETER_TOKEN) + "') is not known.");
            exc.setResponse(new ResponseBuilder().statuscode(200).build());
            return;
        }

        boolean clientIsAuthorized = false;
        String clientId = null;
        if (serverServices.getProvidedServices().getClientDataProvider().isConfidential(token.getClientId())) {
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
            log.debug("Client is not authorized, but confidential.");
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }

        if (!clientId.equals(token.getClientId())) {
            log.debug("Client does not fit to the token.");
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        // valid request

        token.revokeCascade();

        exc.setResponse(new ResponseBuilder().statuscode(200).build());
    }
}
