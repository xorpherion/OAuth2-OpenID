package com.nogiax.security.oauth2openid.tokenanswers;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;

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
        HashMap<String, String> result = new HashMap<>();
//        if (isOpenIdScope()) {
//            String username = getSession().getValue(Constants.LOGIN_USERNAME);
//            String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
//            String scope = getSession().getValue(Constants.PARAMETER_SCOPE);
//            String claims = getSession().getValue(Constants.PARAMETER_CLAIMS);
//            String code = getSession().getValue(Constants.SESSION_AUTHORIZATION_CODE);
//            String grantType = getSession().getValue(Constants.PARAMETER_GRANT_TYPE);
//            String refreshTokenValue = getSession().getValue(Constants.PARAMETER_REFRESH_TOKEN);
//
//
//        }
        return result;
    }


}
