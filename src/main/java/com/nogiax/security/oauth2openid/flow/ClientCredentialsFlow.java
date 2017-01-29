package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;

import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class ClientCredentialsFlow extends Flow {
    public ClientCredentialsFlow(ServerServices serverServices, Exchange exc) {
        super(Constants.GRANT_CLIENT_CREDENTIALS, serverServices, exc);
    }

    @Override
    public Map<String, String> invokeFlow() {
        return null;
    }
}
