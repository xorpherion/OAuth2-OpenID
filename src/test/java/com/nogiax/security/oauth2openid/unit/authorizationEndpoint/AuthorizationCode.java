package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 05.02.2017.
 */
public class AuthorizationCode extends BaseAuthorizationEndpointTests {

    @Override
    public String getResponseType() {
        return Constants.TOKEN_TYPE_CODE;
    }


    @Test
    public Exchange goodPreLoginRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(getResponseType(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
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
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                            () -> assertNotNull(Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_CODE)),
                            () -> assertNull(Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_ACCESS_TOKEN)),
                            () -> assertNull(Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_EXPIRES_IN)),
                            () -> assertEquals(ConstantsTest.CLIENT_DEFAULT_STATE, Common.getQueryParamsFromRedirectResponse(exc).get(Constants.PARAMETER_STATE))
                    );
                });
    }

    public BaseAuthorizationEndpointTests init(AuthorizationServer server) {
        this.server = server;
        return this;
    }
}
