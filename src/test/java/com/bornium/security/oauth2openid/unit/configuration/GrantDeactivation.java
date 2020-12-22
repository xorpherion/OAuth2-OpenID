package com.bornium.security.oauth2openid.unit.configuration;

import com.bornium.http.Exchange;
import com.bornium.http.Method;
import com.bornium.http.RequestBuilder;
import com.bornium.http.ResponseBuilder;
import com.bornium.impl.BearerTokenProvider;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.MembraneServerFunctionality;
import com.bornium.security.oauth2openid.model.WellKnown;
import com.bornium.security.oauth2openid.provider.*;
import com.bornium.security.oauth2openid.providers.ActiveGrantsConfiguration;
import com.bornium.security.oauth2openid.providers.DefaultTimingProvider;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.bornium.security.oauth2openid.unit.Common;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class GrantDeactivation {

    protected AuthorizationServer server;

    @BeforeEach
    public void setUp() throws Exception {
        MembraneConfigProvider membraneConfigProvider = new MembraneConfigProvider(){
            @Override
            public ActiveGrantsConfiguration getActiveGrantsConfiguration() {
                return new ActiveGrantsConfiguration(false,false,false,false,false,false,false);
            }
        };
        server = new AuthorizationServer(new MembraneServerFunctionality(ConstantsTest.URL_AUTHORIZATION_SERVER, new MembraneGrantContextProvider(), new MembraneConsentProvider(), membraneConfigProvider, new MembraneSessionProvider("SC_ID"), new MembraneClientDataProvider(), new MembraneUserDataProvider(), new MembraneTokenPersistenceProvider(), new DefaultTimingProvider(), new BearerTokenProvider()), Common.getIdTokenProvider());
    }

    @Test
    public void authorizationCodeGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.createAuthRequest(Constants.PARAMETER_VALUE_AUTHORIZATION_CODE, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertTrue(Common.getParamsFromRedirectResponse(exc, false).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE))
                    );
                });
    }

    @Test
    public void implicitGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.createAuthRequest(Constants.TOKEN_TYPE_TOKEN, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_STATE);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertTrue(Common.getParamsFromRedirectResponse(exc,false).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_RESPONSE_TYPE))
                    );
                });
    }

    @Test
    public void resourceOwnerPasswordCredentialsGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.preStepAndTokenRequest(null, Constants.PARAMETER_VALUE_PASSWORD, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, null);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void clientCredentialsGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.preStepAndTokenRequest(null, Constants.PARAMETER_VALUE_CLIENT_CREDENTIALS, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, null, null, null);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void refreshTokenGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.preStepAndTokenRequest(null, Constants.PARAMETER_VALUE_REFRESH_TOKEN, null, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, null, null, null);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void revocationDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.createRevocationRequest(null, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_REQUEST_NOT_SUPPORTED))
                    );
                });
    }

    @Test
    public void deviceAuthorizationGrantDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.createDeviceAuthRequest(ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, ConstantsTest.CLIENT_DEFAULT_SCOPE);
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void deviceTokenDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.preStepAndTokenRequest(null, Constants.PARAMETER_VALUE_DEVICE_CODE, null, ConstantsTest.CLIENT_DEFAULT_SCOPE, ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, null, null, "dummy");
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void deviceVerifyDeactivated() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return Common.createDeviceVerificationRequest(ConstantsTest.SERVER_VERIFICATION_ENDPOINT, null, "dummy", Constants.VALUE_YES, ConstantsTest.CLIENT_DEFAULT_SCOPE, "dummy");
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(400, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ERROR).equals(Constants.ERROR_UNSUPPORTED_GRANT_TYPE))
                    );
                });
    }

    @Test
    public void wellKnownFileRespectsDeactivatedGrants() throws Exception{
        Common.testExchangeOn(server,
                () -> {
                    try{
                        return new RequestBuilder()
                                .method(Method.GET)
                                .uri(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_WELL_KNOWN)
                                .buildExchange();
                    } catch (Exception e){
                        return Common.defaultExceptionHandling(e);
                    }
                },
                exc -> {
                    WellKnown wk;
                    try {
                        wk = new ObjectMapper().readValue(exc.getResponse().getBody(), WellKnown.class);
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(200, exc.getResponse().getStatuscode(), "Statuscode was not 400"),
                            () -> assertTrue(wk.getDeviceAuthorizationEndpoint() == null),
                            () -> assertTrue(wk.getRevocationEndpoint() == null),
                            () -> assertTrue(!wk.getResponseTypesSupported().stream().collect(Collectors.joining()).replace("id_token","dummy").contains("code")),
                            () -> assertTrue(!wk.getResponseTypesSupported().stream().collect(Collectors.joining()).replace("id_token","dummy").contains("token")),
                            () -> assertTrue(wk.getGrantTypesSupported().isEmpty())
                    );
                });
    }
}
