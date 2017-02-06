package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class AuthorizationCode extends BaseTokenEndpointTests {
    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_AUTHORIZATION_CODE;
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
    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    @Override
    public String getClientSecret() {
        return ConstantsTest.CLIENT_DEFAULT_SECRET;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public Supplier<Exchange> getPreStep() {
        return new Supplier<Exchange>() {
            @Override
            public Exchange get() {
                try {
                    return new com.nogiax.security.oauth2openid.unit.authorizationEndpoint.AuthorizationCode().init(server).goodPostLoginRequest();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }

    @Test
    public void superiorScopeThanBefore() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),getScope() + " " + Constants.SCOPE_EMAIL,getClientId(),getClientSecret(),getUsername(),getPassword());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_SCOPE, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(400, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void equalScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),getScope(),getClientId(),getClientSecret(),getUsername(),getPassword());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void inferiorScopeThanBefore() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),Constants.SCOPE_OPENID,getClientId(),getClientSecret(),getUsername(),getPassword());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void goodRequest() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),getScope(),getClientId(),getClientSecret(),getUsername(),getPassword());
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
                            () -> assertNotNull(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_REFRESH_TOKEN))
                    );
                });
    }


}
