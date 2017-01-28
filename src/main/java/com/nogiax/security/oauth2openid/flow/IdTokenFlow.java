package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.token.AuthorizationEndpointTokenManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class IdTokenFlow extends Flow {
    public IdTokenFlow(ServerProvider serverProvider, AuthorizationEndpointTokenManager tokenManager, Exchange exc) {
        super(Constants.GRANT_ID_TOKEN, serverProvider, exc);
    }

    @Override
    public Map<String, String> invokeFlow() throws Exception {
        HashMap<String,String> result = new HashMap<>();
        if(isOpenIdScope()){

        }
        return result;
    }

    private boolean isOpenIdScope() throws Exception {
        Session session = getSession();
        String scope = session.getValue(Constants.PARAMETER_SCOPE);
        if(scope != null && scope.equals(Constants.SCOPE_OPENID))
            return true;
        return false;
    }
}