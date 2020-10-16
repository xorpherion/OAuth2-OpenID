package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.unit.Common;
import com.bornium.security.oauth2openid.unit.otherEndpoints.DeviceAuthorizationEndpoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static com.bornium.security.oauth2openid.unit.otherEndpoints.DeviceAuthorizationEndpoint.DEVICE_REQUEST;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TokenEndpoint.DeviceCode")
public class DeviceCode extends BaseTokenEndpointTests {
    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_DEVICE_CODE;
    }

    @Override
    public String getRedirectUri() {
        return null;
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
        return null;
    }

    @Override
    public String getDeviceCode() {
        try {
            DeviceAuthorizationEndpoint deviceAuthorizationEndpoint = new DeviceAuthorizationEndpoint();
            deviceAuthorizationEndpoint.init(server);
            Exchange exchange = deviceAuthorizationEndpoint.goodDeviceCompleteVerificationAckUserCodeAndScope();
            return Common.getBodyParamsFromResponse(
                    ((Exchange) exchange.getProperties().get(DEVICE_REQUEST))).get(Constants.PARAMETER_DEVICE_CODE);
        } catch (Exception e) {
            return Common.defaultExceptionHandling(e);
        }
    }

    @Test
    public void equalScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(), getDeviceCode());
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
    public Exchange goodRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(), getDeviceCode());
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
    public void badDeviceCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(), getDeviceCode() + "bad");
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
    public void missingDeviceCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(), null);
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

    /*
    @Test
    public void useAuthorizationCodeMultipleTimes() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
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
     */

    @Test
    public void wrongClientIdForCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), ConstantsTest.CLIENT_DEFAULT_ID2, ConstantsTest.CLIENT_DEFAULT_SECRET2, getUsername(), getPassword(), getDeviceCode());
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
    public void wrongClientAuthForGrant() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword(), getDeviceCode());
                        exc.getRequest().getHeader().getRawHeaders().replace(Constants.HEADER_AUTHORIZATION.toLowerCase(), Util.encodeToBasicAuthValue(ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET + "23542342"));
                        return exc;
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
