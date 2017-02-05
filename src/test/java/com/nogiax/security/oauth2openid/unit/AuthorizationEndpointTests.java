package com.nogiax.security.oauth2openid.unit;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class AuthorizationEndpointTests extends EndpointTests {

    @Test
    public void goodAuthRequest() throws Exception{
        Common.testExchangeOn(server,
                () ->{
                    try {
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_CODE, ConstantsTest.CLIENT_DEFAULT_ID,ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI,ConstantsTest.CLIENT_DEFAULT_SCOPE,ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) ->{
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303")
                    );
                });
    }

    @Test
    public void badClientid() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_CODE, ConstantsTest.CLIENT_DEFAULT_ID + "NoCorrectClientId",ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI,ConstantsTest.CLIENT_DEFAULT_SCOPE,ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void missingClientid() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_CODE, null,ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI,ConstantsTest.CLIENT_DEFAULT_SCOPE,ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void badRedirectUri() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_CODE, ConstantsTest.CLIENT_DEFAULT_ID,ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI + "somethingsomething",ConstantsTest.CLIENT_DEFAULT_SCOPE,ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_INVALID_REQUEST, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public void badResponseType() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_CODE+"123", ConstantsTest.CLIENT_DEFAULT_ID,ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI,ConstantsTest.CLIENT_DEFAULT_SCOPE,ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE, Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

}
