package com.nogiax.security.oauth2openid.unit;

import com.nogiax.security.oauth2openid.MembraneServerFunctionality;
import com.nogiax.security.oauth2openid.ProvidedServices;
import com.nogiax.security.oauth2openid.server.AuthorizationServer;
import org.junit.jupiter.api.BeforeEach;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class EndpointTests {

    AuthorizationServer server;
    ProvidedServices services;

    @BeforeEach
    public void setUp() throws Exception{
        server = new AuthorizationServer(new MembraneServerFunctionality());
    }

}
