package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.unit.Common;
import com.nogiax.security.oauth2openid.unit.authorizationEndpoint.BaseOpenIdAuthorizationEndpointTests;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Created by Xorpherion on 12.02.2017.
 */
public abstract class BaseOpenIdTokenEndpointTests<T extends BaseOpenIdAuthorizationEndpointTests> extends BaseTokenEndpointTests {

    protected abstract Class<T> getPreClass();

    T endpoint;

    @BeforeEach
    public void setUp() throws Exception{
        endpoint = getPreClass().newInstance();
        endpoint.setUp();
        this.server = endpoint.getServer();
    }

    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_AUTHORIZATION_CODE;
    }

    @Override
    public String getRedirectUri() {
        return endpoint.getRedirectUri();
    }

    @Override
    public String getScope() {
        return endpoint.getScope();
    }

    @Override
    public String getClientId() {
        return endpoint.getClientId();
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
    public Supplier<Exchange> getPreStep() throws Exception {
        return new Supplier<Exchange>() {
            @Override
            public Exchange get() {
                try {
                    return endpoint.goodPostLoginRequest();
                } catch (Exception e) {
                    return Common.defaultExceptionHandling(e);
                }
            }
        };
    }

    @Test
    public void goodRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(),endpoint.isImplicit());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode()),
                            () -> assertNotNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ACCESS_TOKEN)),
                            () -> assertNotNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_EXPIRES_IN)),
                            () -> assertNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_CODE)),
                            () -> assertNotNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ID_TOKEN)),
                            () -> assertNotNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_REFRESH_TOKEN))
                    );
                });
    }


}
