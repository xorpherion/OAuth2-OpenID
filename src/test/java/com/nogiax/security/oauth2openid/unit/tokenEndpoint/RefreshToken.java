package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class RefreshToken {

    protected AuthorizationServer server;


    protected String getClientDefaultScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE;
    }

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER), Common.getIdTokenProvider());
    }

    public Supplier<Exchange> getPreStep() throws Exception {
        return new Supplier<Exchange>() {
            @Override
            public Exchange get() {
                try {
                    return ((AuthorizationCode) new AuthorizationCode().init(server)).goodRequest();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }

    @Test
    public void goodRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndRefreshTokenRequest(getPreStep(), getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
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


    @Test
    public void missingRefreshToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndRefreshTokenRequest(getPreStep(), getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_REFRESH_TOKEN);
                        exc.getRequest().setBody(UriUtil.parametersToQuery(params));
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void badRefreshToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndRefreshTokenRequest(getPreStep(), getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_REFRESH_TOKEN);
                        params.put(Constants.PARAMETER_REFRESH_TOKEN, "3409580743543574390849230");
                        exc.getRequest().setBody(UriUtil.parametersToQuery(params));
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_GRANT, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void useRefreshTokenMultipleTimes() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndRefreshTokenRequest(getPreStep(), getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                        server.invokeOn(exc);
                        exc.setResponse(null);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_GRANT, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void wrongClientIdForRefreshToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndRefreshTokenRequest(getPreStep(), getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                        exc.getRequest().getHeader().getRawHeaders().replace(Constants.HEADER_AUTHORIZATION, Util.encodeToBasicAuthValue(ConstantsTest.CLIENT_DEFAULT_ID2, ConstantsTest.CLIENT_DEFAULT_SECRET2));
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_GRANT, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }
}
