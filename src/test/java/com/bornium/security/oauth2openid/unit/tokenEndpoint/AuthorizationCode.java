package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import com.bornium.http.Exchange;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 06.02.2017.
 */
@DisplayName("TokenEndpoint.AuthorizationCode")
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
                    return new com.bornium.security.oauth2openid.unit.authorizationEndpoint.AuthorizationCode().init(server).goodPostLoginRequest();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }


    /*@Ignore // changed requirements -> scope is now only needed when doing password/credentials flow
    @Test
    public void superiorScopeThanBefore() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope() + " " + Constants.SCOPE_EMAIL, getClientId(), getClientSecret(), getUsername(), getPassword());
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
    }*/

    @Test
    public void equalScope() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
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
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), Constants.SCOPE_PROFILE, getClientId(), getClientSecret(), getUsername(), getPassword());
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
                        return Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
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
    public void badCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_CODE);
                        params.put(Constants.PARAMETER_CODE, "thisissurelynotavalidcode");
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
    public void missingCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_CODE);
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

    @Test
    public void wrongClientIdForCode() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
                        exc.getRequest().getHeader().getRawHeaders().replace(Constants.HEADER_AUTHORIZATION.toLowerCase(), Util.encodeToBasicAuthValue(ConstantsTest.CLIENT_DEFAULT_ID2, ConstantsTest.CLIENT_DEFAULT_SECRET2));
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
    public void missingRedirectUri() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_REDIRECT_URI);
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
    public void badRedirectUri() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
                        Map<String, String> params = UriUtil.queryToParameters(exc.getRequest().getBody());
                        params.remove(Constants.PARAMETER_REDIRECT_URI);
                        params.put(Constants.PARAMETER_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI + "43897589234");
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
    public void wrongClientAuthForGrant() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.preStepAndTokenRequest(getPreStep(), getGrantType(), getRedirectUri(), getScope(), getClientId(), getClientSecret(), getUsername(), getPassword());
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
