package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.server.endpoints.Endpoint;

import java.util.List;

public interface EndpointFactory {
    Endpoint createLogin(AuthorizationServer serverServices);
}
