package com.bornium.security.oauth2openid.unit.otherEndpoints;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.MembraneServerFunctionality;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.unit.Common;
import com.bornium.security.oauth2openid.unit.tokenEndpoint.DeviceCode;
import com.predic8.membrane.core.http.Header;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("DeviceAuthorizationEndpoint")
public class DeviceAuthorizationEndpoint {

    public static final String DEVICE_REQUEST = "deviceRequest";

    public AuthorizationServer getServer() {
        return server;
    }

    protected AuthorizationServer server;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER), Common.getIdTokenProvider());
    }

    public DeviceAuthorizationEndpoint init(AuthorizationServer server) {
        this.server = server;
        return this;
    }

    @Test
    public void goodDeviceAuthRequestTest() throws Exception {
        goodDeviceAuthRequest();
    }

    public Exchange goodDeviceAuthRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(getClientId(), getClientSecret(), getScope());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode(), "Statuscode was not 200"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get("device_code").length() > 10),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get("user_code").length() > 5),
                            () -> assertEquals((Integer) 600, (Integer) (Object) Common.getBodyParamsFromResponse(exc).get("expires_in"))
                    );
                });
    }

    @Test
    public void badClientid() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(getClientId() + "NoCorrectClientId", getClientSecret(), getScope());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_CLIENT, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(400, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void badClientSecret() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(getClientId(), getClientSecret() + "bad", getScope());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_ACCESS_DENIED, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals(401, exc.getResponse().getStatuscode())
                    );
                });
    }

    @Test
    public void missingClientSecret() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(getClientId(), null, getScope());
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
    public void missingClientidAndClientSecret() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(null, null, getScope());
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
    public void invalidScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createDeviceAuthRequest(getClientId(), getClientSecret(), "this is surely not a valid scope");
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
                        return Common.createDeviceAuthRequest(getClientId(), getClientSecret(), null);
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
    public void goodCompleteVerificationRequestTest() throws Exception {
        goodCompleteVerificationRequest();
    }

    public Exchange goodCompleteVerificationRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceAuthRequest();
                        Map<String, String> deviceAuthResonseParams = Common.getBodyParamsFromResponse(exc);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(deviceAuthResonseParams.get(Constants.PARAMETER_VERIFICATION_URI_COMPLETE), null, null, null, null));
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
    public void goodVerificationRequestTest() throws Exception {
        goodVerificationRequest();
    }

    public Exchange goodVerificationRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceAuthRequest();
                        Map<String, String> deviceAuthResonseParams = Common.getBodyParamsFromResponse(exc);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(deviceAuthResonseParams.get(Constants.PARAMETER_VERIFICATION_URI), null, null, null, null));
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
    public void goodLoginAfterCompleteVerificationTest() throws Exception {
        goodLoginAfterCompleteVerification();
    }

    public Exchange goodLoginAfterCompleteVerification() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodCompleteVerificationRequest();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return piggyBack(exc, Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc)));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_VERIFICATION, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public void goodLoginAfterVerificationTest() throws Exception {
        goodLoginAfterVerification();
    }

    public Exchange goodLoginAfterVerification() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodVerificationRequest();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        return piggyBack(exc, Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc)));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_VERIFICATION, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public void goodDeviceCompleteVerificationOpenFormTest() throws Exception {
        goodDeviceCompleteVerificationOpenForm();
    }

    public Exchange goodDeviceCompleteVerificationOpenForm() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodLoginAfterCompleteVerification();
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), null, null, null));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertNotNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE)),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void goodDeviceCompleteVerificationAckUserCodeTest() throws Exception {
        goodDeviceCompleteVerificationAckUserCode();
    }

    public Exchange goodDeviceCompleteVerificationAckUserCode() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceCompleteVerificationOpenForm();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), loginParams.get("user_code"), "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertNotNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE)),
                            () -> assertEquals(getScope(), Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void goodDeviceVerificationWithGoodUserCodeTest() throws Exception {
        goodDeviceVerificationWithGoodUserCode();
    }

    public Exchange goodDeviceVerificationWithGoodUserCode() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceVerificationOpenForm();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String userCode = Common.getBodyParamsFromResponse(((Exchange)exc.getProperties().get(DEVICE_REQUEST))).get(Constants.PARAMETER_USER_CODE);
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), userCode, "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertTrue(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE).length() > 5),
                            () -> assertEquals(getScope(), Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void goodDeviceVerificationWithBadUserCodeTest() throws Exception {
        goodDeviceVerificationWithBadUserCode();
    }

    public Exchange goodDeviceVerificationWithBadUserCode() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceVerificationOpenForm();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), "bad", "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertEquals("bad", Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE)),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void goodDeviceCompleteVerificationWithGoodUserCodeAckScopeTest() throws Exception {
        goodDeviceCompleteVerificationWithGoodUserCodeAckScope();
    }

    public Exchange goodDeviceCompleteVerificationWithGoodUserCodeAckScope() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceVerificationWithGoodUserCode();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), loginParams.get("user_code"), "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode(), "Statuscode was not 200"),
                            () -> assertTrue(exc.getResponse().getBody().contains("successfully authorized"))
                    );
                });
    }

    @Test
    public void reuseUserCodeTest() throws Exception {
        reuseUserCode();
    }

    public Exchange reuseUserCode() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceCompleteVerificationWithGoodUserCodeAckScope();
                        String userCode = Common.getBodyParamsFromResponse(
                                ((Exchange) exc.getProperties().get(DEVICE_REQUEST))).get(Constants.PARAMETER_USER_CODE);

                        return piggyBack(exc, Common.createDeviceVerificationRequest(ConstantsTest.SERVER_VERIFICATION_ENDPOINT, Common.extractSessionCookie(exc), userCode, "yes", null));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE)),
                            () -> assertEquals(Constants.ERROR_INVALID_GRANT, Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void goodDeviceCompleteVerificationWithGoodUserCodeRejectedScopeTest() throws Exception {
        goodDeviceCompleteVerificationWithGoodUserCodeRejectedScope();
    }

    public Exchange goodDeviceCompleteVerificationWithGoodUserCodeRejectedScope() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceCompleteVerificationAckUserCode();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), loginParams.get("user_code"), "no", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertNotNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE)),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void goodDeviceCompleteVerificationAckUserCodeAndScopeTest() throws Exception {
        goodDeviceCompleteVerificationAckUserCodeAndScope();
    }

    public Exchange goodDeviceCompleteVerificationAckUserCodeAndScope() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceCompleteVerificationAckUserCode();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), loginParams.get("user_code"), "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode(), "Statuscode was not 200"),
                            () -> assertTrue(exc.getResponse().getBody().contains("successfully authorized"))
                    );
                });
    }

    @Test
    public void reuseUserCodeAfterRejectionTest() throws Exception {
        reuseUserCodeAfterRejection();
    }

    public Exchange reuseUserCodeAfterRejection() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodDeviceCompleteVerificationWithGoodUserCodeRejectedScope();
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), loginParams.get("user_code"), "yes", loginParams.get("scope")));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE)),
                            () -> assertEquals(Constants.ERROR_INVALID_GRANT, Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void goodDeviceVerificationOpenFormTest() throws Exception {
        goodDeviceVerificationOpenForm();
    }

    public Exchange goodDeviceVerificationOpenForm() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodLoginAfterVerification();
                        String newLocation = exc.getResponse().getHeader().getValue(Header.LOCATION);
                        return piggyBack(exc, Common.createDeviceVerificationRequest(new URL(exc.getRequest().getUri().toURL(), newLocation).toString(), Common.extractSessionCookie(exc), null, null, null));

                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_ERROR)),
                            () -> assertNotNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_USER_CODE)),
                            () -> assertNull(Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION)).get(Constants.PARAMETER_SCOPE))
                    );
                });
    }

    @Test
    public void loginWrongUsernameTest() throws Exception {
        loginWrongUsername();
    }

    public Exchange loginWrongUsername() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodCompleteVerificationRequest();
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
    public void loginWrongPasswordTest() throws Exception {
        loginWrongPassword();
    }

    public Exchange loginWrongPassword() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodCompleteVerificationRequest();
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

    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    public String getScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE;
    }

    public boolean isImplicit() {
        return false;
    }

    public String getClientSecret() {
        return ConstantsTest.CLIENT_DEFAULT_SECRET;
    }


    /**
     * This method piggybacks the device exchange (result of {@link #goodDeviceAuthRequest()}) as a property on all
     * other exchanges (up to {@link #goodCompleteVerificationRequest()}), so that
     * {@link DeviceCode#getDeviceCode()} can retrieve the original device_code
     * returned from the AS.
     */
    private Exchange piggyBack(Exchange previousExchange, Exchange currentExchange) {
        Exchange deviceExchange = (Exchange) previousExchange.getProperties().get(DEVICE_REQUEST);
        if (deviceExchange == null)
            deviceExchange = previousExchange;
        currentExchange.getProperties().put(DEVICE_REQUEST, deviceExchange);
        return currentExchange;
    }

}
