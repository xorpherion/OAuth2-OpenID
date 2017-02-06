package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public abstract class BaseTokenEndpointTests {

    protected AuthorizationServer server;

    public abstract String getGrantType();
    public abstract String getRedirectUri();
    public abstract String getScope();
    public abstract String getClientId();
    public abstract String getClientSecret();
    public abstract String getUsername();
    public abstract String getPassword();
    public abstract Supplier<Exchange> getPreStep();

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
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType() +"123",getRedirectUri(),getScope(),getClientId(),getClientSecret(),getUsername(),getPassword());
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
                        return Common.preStepAndTokenRequest(getPreStep(),null,getRedirectUri(),getScope(),getClientId(),getClientSecret(),getUsername(),getPassword());
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
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),getScope() + "maybe this scope is not supported?",getClientId(),getClientSecret(),getUsername(),getPassword());
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
    public void missingScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),null,getClientId(),getClientSecret(),getUsername(),getPassword());
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
                        return Common.preStepAndTokenRequest(getPreStep(),getGrantType(),getRedirectUri(),getScope(),getClientId(),getClientSecret()+"wrong secret",getUsername(),getPassword());
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
