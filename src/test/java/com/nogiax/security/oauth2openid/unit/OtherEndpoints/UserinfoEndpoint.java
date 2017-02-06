package com.nogiax.security.oauth2openid.unit.OtherEndpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import com.nogiax.security.oauth2openid.unit.Common;
import com.nogiax.security.oauth2openid.unit.tokenEndpoint.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class UserinfoEndpoint {

    protected AuthorizationServer server;
    protected String accessToken;

    @BeforeEach
    public void setUp() throws Exception {
        server = new AuthorizationServer(new MembraneServerFunctionality());
        accessToken = getAccessToken();
    }

    public String getAccessToken() throws Exception {
        return String.valueOf(new ObjectMapper().readValue(new AuthorizationCode().init(server).goodRequest().getResponse().getBody(),Map.class).get(Constants.PARAMETER_ACCESS_TOKEN));
    }

    @Test
    public void goodRequest() throws Exception {
        Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createUserinfoRequest(accessToken,Constants.PARAMETER_VALUE_BEARER);
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
