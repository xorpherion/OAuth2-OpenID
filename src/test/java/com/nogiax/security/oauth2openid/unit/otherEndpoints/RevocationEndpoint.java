package com.nogiax.security.oauth2openid.unit.otherEndpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import com.nogiax.security.oauth2openid.unit.tokenEndpoint.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 07.02.2017.
 */
public class RevocationEndpoint {

    protected AuthorizationServer server;
    protected String accessToken;
    protected String refreshToken;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality());
        accessToken = getAccessToken();
    }

    public String getAccessToken() throws Exception {
        return String.valueOf(new ObjectMapper().readValue(new AuthorizationCode().init(server).goodRequest().getResponse().getBody(), Map.class).get(Constants.PARAMETER_ACCESS_TOKEN));
    }

    @Test
    public void goodRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createRevocationRequest(accessToken, ConstantsTest.CLIENT_DEFAULT_ID,ConstantsTest.CLIENT_DEFAULT_SECRET);
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
}
