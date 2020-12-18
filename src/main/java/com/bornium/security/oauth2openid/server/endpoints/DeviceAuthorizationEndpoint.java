package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Method;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.User;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.responsegenerators.DeviceAuthorizationResponseGenerator;
import com.bornium.security.oauth2openid.server.AuthorizationServer;

import java.util.Map;

public class DeviceAuthorizationEndpoint extends Endpoint {

    public DeviceAuthorizationEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_DEVICE_AUTHORIZATION);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        if (exc.getRequest().getMethod() != Method.POST) {
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        boolean clientIsAuthorized = false;
        String clientId = null;
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
        Session session = serverServices.getProvidedServices().getSessionProvider().getSession(exc);
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
        params = Parameters.stripEmptyParams(params);

        GrantContext ctx = serverServices.getProvidedServices().getGrantContextDaoProvider().findByIdOrCreate(""); //TODO

        if (clientId == null)
            clientId = params.get(Constants.PARAMETER_CLIENT_ID);
        if (clientId == null) {
            log.debug("No clientId detected.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }
        if (!serverServices.getProvidedServices().getClientDataProvider().clientExists(clientId)) {
            log.debug("Client ('" + clientId + "') does not exist.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_CLIENT));
            return;
        }
        if (!clientIsAuthorized && serverServices.getProvidedServices().getClientDataProvider().isConfidential(clientId)) {
            log.debug("Client is confidential and client_secret incorrect.");
            exc.setResponse(answerWithError(401, Constants.ERROR_ACCESS_DENIED));
            return;
        }
        ctx.putValue(Constants.PARAMETER_CLIENT_ID, clientId);

        if (!serverServices.getSupportedScopes().scopesSupported(params.get(Constants.PARAMETER_SCOPE))) {
            log.debug("Scope ('" + params.get(Constants.PARAMETER_SCOPE) + "') not supported.");
            exc.setResponse(answerWithError(400, Constants.ERROR_INVALID_SCOPE));
            return;
        }
        ctx.putValue(Constants.PARAMETER_SCOPE, params.get(Constants.PARAMETER_SCOPE));

        Map<String, String> responseBody = new DeviceAuthorizationResponseGenerator(serverServices, ctx).invokeResponse();
        copyResponseIntoContext(ctx, responseBody);

        ctx.setIdentifier(responseBody.get(Constants.PARAMETER_DEVICE_CODE));
        serverServices.getProvidedServices().getGrantContextDaoProvider().persist(ctx);

        GrantContext deepCopyForUserCode = serverServices.getProvidedServices().getGrantContextDaoProvider().deepCopy(ctx);
        deepCopyForUserCode.setIdentifier(responseBody.get(Constants.PARAMETER_USER_CODE));
        serverServices.getProvidedServices().getGrantContextDaoProvider().persist(deepCopyForUserCode);

        exc.setResponse(okWithJSONBody(responseBody));
    }

    private void copyResponseIntoContext(GrantContext ctx, Map<String, String> responseBody) {
        responseBody.entrySet().stream().forEach(e -> {
            try {
                ctx.putValue(e.getKey(),String.valueOf(e.getValue()));
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
    }
}
