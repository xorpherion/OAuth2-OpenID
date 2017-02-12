package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 05.02.2017.
 */
@DisplayName("AuthorizationEndpoint.AuthorizationCode")
public class AuthorizationCode extends BaseAuthorizationEndpointTests {

    @Override
    public String getResponseType() {
        return Constants.TOKEN_TYPE_CODE;
    }

    @Override
    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    @Override
    public String getRedirectUri() {
        return ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI;
    }

    @Override
    public String getScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE;
    }

    @Override
    public String getState() {
        return ConstantsTest.CLIENT_DEFAULT_STATE;
    }

    @Override
    public boolean isImplicit() {
        return false;
    }

    @Override
    public Consumer<Exchange> validateResultPostLogin() {
        return exc -> assertAll(
                Common.getMethodName(),
                () -> assertEquals(303, exc.getResponse().getStatuscode()),
                () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                () -> assertNotNull(Common.getParamsFromRedirectResponse(exc,isImplicit()).get(Constants.PARAMETER_CODE)),
                () -> assertNull(Common.getParamsFromRedirectResponse(exc,isImplicit()).get(Constants.PARAMETER_ACCESS_TOKEN)),
                () -> assertNull(Common.getParamsFromRedirectResponse(exc,isImplicit()).get(Constants.PARAMETER_EXPIRES_IN)),
                () -> assertEquals(ConstantsTest.CLIENT_DEFAULT_STATE, Common.getParamsFromRedirectResponse(exc,isImplicit()).get(Constants.PARAMETER_STATE))
        );
    }

}
