package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.server.SupportedClaims;
import com.nogiax.security.oauth2openid.token.IdTokenProvider;
import com.nogiax.security.oauth2openid.unit.Common;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Created by Xorpherion on 05.02.2017.
 */
public abstract class BaseAuthorizationEndpointTests {

    protected AuthorizationServer server;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER),Common.getIdTokenProvider());
    }

    public abstract String getResponseType();
    public abstract String getClientId();
    public abstract String getRedirectUri();
    public abstract String getScope();
    public abstract String getState();

    public abstract Consumer<Exchange> validateResultPostLogin();

    @Test
    public Exchange goodPreLoginRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState());
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
    public Exchange goodPostLoginRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodConsent();
                        return Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                validateResultPostLogin());
    }

    @Test
    public void badClientid() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(),getClientId() + "NoCorrectClientId",getRedirectUri(),getScope(),getState());
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
                        return Common.createAuthRequest(getResponseType(),null,getRedirectUri(),getScope(),getState());
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
                        return Common.createAuthRequest(getResponseType(),getClientId(),getRedirectUri()+"somethingsomething",getScope(),getState());
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
                        return Common.createAuthRequest(getResponseType(),getClientId(),null,getScope(),getState());
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
                        return Common.createAuthRequest(getResponseType()+123,getClientId(),getRedirectUri(),getScope(),getState());
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
                        return Common.createAuthRequest(null,getClientId(),getRedirectUri(),getScope(),getState());
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
                        return Common.createAuthRequest(getResponseType(),getClientId(),getRedirectUri(),"this is surely not a valid scope",getState());
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
                        return Common.createAuthRequest(getResponseType(),getClientId(),getRedirectUri(),null,getState());
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
