package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class Password extends BaseTokenEndpointTests {
    @Override
    public String getGrantType() {
        return Constants.PARAMETER_VALUE_PASSWORD;
    }

    @Override
    public Exchange preStepAndTokenRequest(String grantType, String scope, boolean authenticate, boolean authenticateCorrectly) throws Exception {

        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAMETER_GRANT_TYPE, grantType);
        params.put(Constants.PARAMETER_USERNAME, ConstantsTest.USER_DEFAULT_NAME);
        params.put(Constants.PARAMETER_PASSWORD, ConstantsTest.USER_DEFAULT_PASSWORD);
        params.put(Constants.PARAMETER_SCOPE, scope);

        params = Parameters.stripEmptyParams(params);

        if (!authenticate)
            return new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).buildExchange();
        String clientId = ConstantsTest.CLIENT_DEFAULT_ID;
        String clientSecret = ConstantsTest.CLIENT_DEFAULT_SECRET;
        if (!authenticateCorrectly)
            clientSecret += "sdjfhnsdkfsdkfsdgjklsdklfsdnfjksnjkl";
        String authHeader = Util.encodeToBasicAuthValue(clientId, clientSecret);
        return new RequestBuilder().uri(ConstantsTest.SERVER_TOKEN_ENDPOINT).method(Method.POST).body(UriUtil.parametersToQuery(params)).header(Constants.HEADER_AUTHORIZATION, authHeader).buildExchange();
    }
}
