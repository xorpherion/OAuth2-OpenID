package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class AuthorizationCode extends BaseTokenEndpointTests {
    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_AUTHORIZATION_CODE;
    }

    @Override
    public Exchange preStepAndTokenRequest(String grantType, String scope, boolean authenticate, boolean authenticateCorrectly) throws Exception {
        Exchange exc = new com.nogiax.security.oauth2openid.unit.authorizationEndpoint.AuthorizationCode().init(server).goodPostLoginRequest();
        String cookie = Common.extractSessionCookie(exc);
        Map<String, String> responseParams = Common.getQueryParamsFromRedirectResponse(exc);

        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_GRANT_TYPE, grantType);
        params.put(Constants.PARAMETER_CODE, responseParams.get(Constants.PARAMETER_CODE));
        params.put(Constants.PARAMETER_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI);
        params.put(Constants.PARAMETER_SCOPE, scope);

        params = Parameters.stripEmptyParams(params);

        if (!authenticate)
            return new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_COOKIE, cookie).buildExchange();
        String clientId = ConstantsTest.CLIENT_DEFAULT_ID;
        String clientSecret = ConstantsTest.CLIENT_DEFAULT_SECRET;
        if (!authenticateCorrectly)
            clientSecret += "sdjfhnsdkfsdkfsdgjklsdklfsdnfjksnjkl";
        String authHeader = Util.encodeToBasicAuthValue(clientId, clientSecret);
        return new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_AUTHORIZATION, authHeader).header(Constants.HEADER_COOKIE, cookie).buildExchange();
    }

    @Test
    public void superiorScopeThanBefore() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return preStepAndTokenRequest(getGrantType(), ConstantsTest.CLIENT_DEFAULT_SCOPE + " " + Constants.SCOPE_EMAIL, true, true);
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
}
