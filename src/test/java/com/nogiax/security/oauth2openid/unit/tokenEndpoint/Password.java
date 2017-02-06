package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class Password extends BaseTokenEndpointTests {
    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_PASSWORD;
    }

    @Override
    public String getRedirectUri() {
        return null;
    }

    @Override
    public String getScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE;
    }

    @Override
    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    @Override
    public String getClientSecret() {
        return ConstantsTest.CLIENT_DEFAULT_SECRET;
    }

    @Override
    public String getUsername() {
        return ConstantsTest.USER_DEFAULT_NAME;
    }

    @Override
    public String getPassword() {
        return ConstantsTest.USER_DEFAULT_PASSWORD;
    }

    @Override
    public Supplier<Exchange> getPreStep() {
        return null;
    }
}
