package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.token.IdTokenVerifier;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Created by Xorpherion on 12.02.2017.
 */
public class OpenIdRefreshToken extends RefreshToken {

    private OpenIdCode endpoint;

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        endpoint = new OpenIdCode();
        endpoint.setUp();
        this.server = endpoint.server;
    }

    @Override
    public Supplier<Exchange> getPreStep() throws Exception {
        return new Supplier<Exchange>() {
            @Override
            public Exchange get() {
                try {
                    return endpoint.goodRequest();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }

    @Override
    protected String getClientDefaultScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE_OPENID;
    }

    @Test
    public void compareRefreshIdToken() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        IdTokenVerifier verifier = new IdTokenVerifier(server.getServerServices().getTokenManager().getJwk());
                        Exchange exc = getPreStep().get();
                        String idToken = Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ID_TOKEN);
                        Map<String,String> idTokenClaims = verifier.verifyAndGetClaims(idToken,server.getServerServices().getProvidedServices().getIssuer(),ConstantsTest.CLIENT_DEFAULT_ID);
                        exc = Common.preStepAndRefreshTokenRequest(exc, getClientDefaultScope(), ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET);

                        exc = server.invokeOn(exc);
                        String secondIdToken = Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ID_TOKEN);
                        Map<String,String> secondIdTokenClaims = verifier.verifyAndGetClaims(secondIdToken,server.getServerServices().getProvidedServices().getIssuer(),ConstantsTest.CLIENT_DEFAULT_ID);
                        assertAll(
                                Common.getMethodName(),
                                () -> assertEquals(idTokenClaims.get(Constants.CLAIM_ISS),secondIdTokenClaims.get(Constants.CLAIM_ISS)),
                                () -> assertEquals(idTokenClaims.get(Constants.CLAIM_SUB),secondIdTokenClaims.get(Constants.CLAIM_SUB)),
                                () -> assertEquals(idTokenClaims.get(Constants.CLAIM_AZP),secondIdTokenClaims.get(Constants.CLAIM_AZP)),
                                () -> assertEquals(idTokenClaims.get(Constants.CLAIM_AUD),secondIdTokenClaims.get(Constants.CLAIM_AUD))
                        );

                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                });
    }
}
