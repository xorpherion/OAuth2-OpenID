package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 05.02.2017.
 */
public abstract class BaseAuthorizationEndpointTests {

    protected AuthorizationServer server;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality());
    }

    public abstract String getResponseType();

    @Test
    public abstract Exchange goodPreLoginRequest() throws Exception;

    @Test
    public abstract Exchange goodPostLoginRequest() throws Exception;

    @Test
    public void badClientid() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID + "NoCorrectClientId", ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
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
    public void missingClientid() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), null, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
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
    public void badRedirectUri() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI + "somethingsomething", ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
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
    public void missingRedirectUri() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID, null, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
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
    public void badResponseType() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType() + "123", ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public void missingResponseType() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(null, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public void invalidScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, "this is surely not a supported scope", ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_SCOPE, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public void missingScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, null, ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_SCOPE, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange goodLogin() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodPreLoginRequest();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_CONSENT, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange goodConsent() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodLogin();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_AFTER_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange loginWrongUsername() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodPreLoginRequest();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME + "myusernameisreallycool", ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange loginWrongPassword() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodPreLoginRequest();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD + "mypasswordiswrong", loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange consentNotGiven() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodLogin();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return Common.createConsentRequest(Constants.VALUE_NO, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_ACCESS_DENIED, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }


}
