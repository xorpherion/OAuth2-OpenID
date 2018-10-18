package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import org.junit.jupiter.api.DisplayName;

/**
 * Created by Xorpherion on 12.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCodeIdToken")
public class OpenIdCodeIdToken extends BaseOpenIdTokenEndpointTests<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken> {
    @Override
    protected Class<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken> getPreClass() {
        return com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken.class;
    }
}
