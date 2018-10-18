package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import org.junit.jupiter.api.DisplayName;

/**
 * Created by Xorpherion on 12.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCode")
public class OpenIdCode extends BaseOpenIdTokenEndpointTests<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode> {
    @Override
    protected Class<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode> getPreClass() {
        return com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode.class;
    }
}
