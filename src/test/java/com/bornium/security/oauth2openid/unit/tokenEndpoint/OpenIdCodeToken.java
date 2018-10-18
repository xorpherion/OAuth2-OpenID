package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import org.junit.jupiter.api.DisplayName;

/**
 * Created by Xorpherion on 12.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCodeToken")
public class OpenIdCodeToken extends BaseOpenIdTokenEndpointTests<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken> {
    @Override
    protected Class<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken> getPreClass() {
        return com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken.class;
    }
}
