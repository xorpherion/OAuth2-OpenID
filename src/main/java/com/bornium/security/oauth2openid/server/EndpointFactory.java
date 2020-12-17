package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.server.endpoints.Endpoint;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginEndpointBase;

import java.util.List;

public interface EndpointFactory {
    LoginEndpointBase createEndpoint(AuthorizationServer serverServices);
}
