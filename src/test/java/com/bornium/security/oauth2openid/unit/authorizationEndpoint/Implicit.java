package com.bornium.security.oauth2openid.unit.authorizationEndpoint;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;

import java.net.URI;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 05.02.2017.
 */
@DisplayName("AuthorizationEndpoint.Implicit")
public class Implicit extends BaseAuthorizationEndpointTests {
    @Override
    public String getResponseType() {
        return Constants.TOKEN_TYPE_TOKEN;
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
        return true;
    }


    @Override
    public Consumer<Exchange> validateResultPostLogin() {
        return (exc) -> {
            assertAll(
                    Common.getMethodName(),
                    () -> assertEquals(303, exc.getResponse().getStatuscode()),
                    () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ACCESS_TOKEN)),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_EXPIRES_IN)),
                    () -> assertNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_CODE)),
                    () -> assertNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_REFRESH_TOKEN)),
                    () -> assertEquals(ConstantsTest.CLIENT_DEFAULT_STATE, Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_STATE))
            );
        };
    }
}
