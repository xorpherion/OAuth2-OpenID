package com.nogiax.security.oauth2openid.unit.otherEndpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import com.nogiax.security.oauth2openid.unit.tokenEndpoint.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class UserinfoEndpoint {

    protected AuthorizationServer server;
    protected String accessToken;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER), Common.getIdTokenProvider());
        accessToken = getAccessToken();
    }

    public String getAccessToken() throws Exception {
        return String.valueOf(new ObjectMapper().readValue(((AuthorizationCode) new AuthorizationCode().init(server)).goodRequest().getResponse().getBody(), Map.class).get(Constants.PARAMETER_ACCESS_TOKEN));
    }

    @Test
    public void goodRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createUserinfoRequest(accessToken, Constants.PARAMETER_VALUE_BEARER);
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
    public void badToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createUserinfoRequest(accessToken + "1215415151515145415", Constants.PARAMETER_VALUE_BEARER);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(401, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_TOKEN, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void missingToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createUserinfoRequest(null, Constants.PARAMETER_VALUE_BEARER);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(401, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_TOKEN, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void missingTokenType() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createUserinfoRequest(accessToken, null);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(401, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_TOKEN, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void goodRequestThenRevokeThanBadRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createUserinfoRequest(accessToken, Constants.PARAMETER_VALUE_BEARER);
                        assertEquals(200, server.invokeOn(exc).getResponse().getStatuscode());
                        Exchange revoke = Common.createRevocationRequest(accessToken, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                        assertEquals(200, server.invokeOn(revoke).getResponse().getStatuscode());
                        exc.setResponse(null);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(401, exc.getResponse().getStatuscode()),
                            () -> assertEquals(Constants.ERROR_INVALID_TOKEN, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }
}
