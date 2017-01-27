package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.http.Response;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.Session;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationEndpoint extends Endpoint{

    public AuthorizationEndpoint(ServerProvider serverProvider) {
        super(serverProvider, Constants.ENDPOINT_AUTHORIZATION);
    }

    @Override
    public boolean checkParametersOAuth2(Exchange exc) throws Exception {
        if(!isLoggedInAndHasGivenConsent(exc)) {
            Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
            params = Parameters.stripEmptyParams(params);

            if (redirectUriOrClientIdProblem(params)) {
                exc.setResponse(informResourceOwnerError(Constants.ERROR_INVALID_REQUEST));
                return false;
            }

            if (params.get(Constants.PARAMETER_RESPONSE_TYPE) == null || params.get(Constants.PARAMETER_CLIENT_ID) == null || params.get(Constants.PARAMETER_REDIRECT_URI) == null) {
                exc.setResponse(redirectToCallbackWithError(params.get(Constants.PARAMETER_REDIRECT_URI), Constants.ERROR_INVALID_REQUEST));
                return false;
            }

            return true;
        }
        return true;
    }




    private boolean redirectUriOrClientIdProblem(Map<String, String> params) {
        return params.get(Constants.PARAMETER_REDIRECT_URI) == null
                || !Parameters.redirectUriIsAbsolute(params.get(Constants.PARAMETER_REDIRECT_URI))
                || params.get(Constants.PARAMETER_CLIENT_ID) == null
                || !clientExists(params.get(Constants.PARAMETER_CLIENT_ID));
    }




    @Override
    public boolean invokeOnOAuth2(Exchange exc) throws Exception {
        log.info("Authorization endpoint oauth2");
        if(!isLoggedInAndHasGivenConsent(exc)) {

            Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
            params = Parameters.stripEmptyParams(params);

            Session session = serverProvider.getSessionProvider().getSession(exc);
            for (String param : params.keySet())
                session.putValue(param, params.get(param));

            exc.setResponse(redirectToLogin(new HashMap<>()));

            return true;
        }
        return true;
    }

    @Override
    public boolean checkParametersOpenID(Exchange exc) throws Exception {
        if(!isLoggedInAndHasGivenConsent(exc)) {
            return true;
        }
        return true;
    }

    @Override
    public boolean invokeOnOpenId(Exchange exc) throws Exception {
        log.info("Authorization endpoint openid");
        if(!isLoggedInAndHasGivenConsent(exc)) {
            return true;
        }
        return true;
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getUri().getQuery());
        return params.get(Constants.PARAMETER_SCOPE);
    }


}
