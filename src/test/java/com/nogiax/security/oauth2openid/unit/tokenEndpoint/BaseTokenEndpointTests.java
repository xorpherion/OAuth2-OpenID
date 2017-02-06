package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public abstract class BaseTokenEndpointTests {

    protected AuthorizationServer server;

    public abstract String getGrantType();

    public abstract Exchange preStepAndTokenRequest(String grantType, String scope, boolean authenticate, boolean authenticateCorreclty) throws Exception;

    public BaseTokenEndpointTests(AuthorizationServer server) {
        this.server = server;
    }

    public BaseTokenEndpointTests() {
        this.server = null;
    }

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality());
    }

    @Test
    public void badGrantType() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(getGrantType() + "123", ConstantsTest.CLIENT_DEFAULT_SCOPE, true, true);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(400, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void missingGrantType() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(null, ConstantsTest.CLIENT_DEFAULT_SCOPE, true, true);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(400, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void unsupportedScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(getGrantType(), ConstantsTest.CLIENT_DEFAULT_SCOPE + "maybe this scope is not supported?", true, true);
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
                        return preStepAndTokenRequest(getGrantType(), ConstantsTest.CLIENT_DEFAULT_SCOPE, true, true);
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
                        return preStepAndTokenRequest(getGrantType(), Constants.SCOPE_OPENID, true, true);
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
    public void missingScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(getGrantType(), null, true, true);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(400, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void wrongAuthentication() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(getGrantType(), ConstantsTest.CLIENT_DEFAULT_SCOPE, true, false);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(401, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_ACCESS_DENIED, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }
}
