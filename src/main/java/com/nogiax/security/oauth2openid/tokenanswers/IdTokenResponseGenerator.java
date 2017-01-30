package com.nogiax.security.oauth2openid.tokenanswers;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.Session;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class IdTokenResponseGenerator extends ResponseGenerator {
    public IdTokenResponseGenerator(ServerServices serverServices, Exchange exc) {
        super(Constants.TOKEN_TYPE_ID_TOKEN, serverServices, exc);
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
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
