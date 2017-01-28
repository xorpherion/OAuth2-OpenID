package com.nogiax.security.oauth2openid.flow;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;

import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class CodeFlow extends Flow {

    public CodeFlow(ServerProvider serverProvider, Exchange exc) {
        super(Constants.GRANT_CODE, serverProvider, exc);
    }

    @Override
    public Map<String, String> invokeFlow() {
        return null;
    }
}
