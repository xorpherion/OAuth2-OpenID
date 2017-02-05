package com.nogiax.security.oauth2openid.unit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.http.RequestBuilder;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.server.endpoints.Endpoint;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class Common {

    public static String getMethodName(){
        return Thread.currentThread().getStackTrace()[2].getMethodName();
    }

    public static <T> T defaultExceptionHandling(Exception e){
        e.printStackTrace();
        return null;
    }

    public static void testExchangeOn(AuthorizationServer server, Supplier<Exchange> requestSupplier, Consumer<Exchange> resultValidation) throws Exception {
        Exchange exc = requestSupplier.get();
        Exchange result = server.invokeOn(exc);
        resultValidation.accept(result);
    }

    public static Exchange createAuthRequest(String responseType, String clientId, String redirectUrl, String scope, String state) throws URISyntaxException {
        Map<String,String> params = Parameters.createParams(
                Constants.PARAMETER_RESPONSE_TYPE, responseType,
                Constants.PARAMETER_CLIENT_ID, clientId,
                Constants.PARAMETER_REDIRECT_URI,redirectUrl,
                Constants.PARAMETER_SCOPE, scope,
                Constants.PARAMETER_STATE, state
                );
        params = Parameters.stripEmptyParams(params);

        return new RequestBuilder().uri(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT+ "?" + UriUtil.parametersToQuery(params)).method(Method.GET).buildExchange();
    }

    public static Map<String,String> getBodyParamsFromResponse(Exchange exc) throws IOException {
        return new ObjectMapper().readValue(exc.getResponse().getBody(),Map.class);
    }
}
