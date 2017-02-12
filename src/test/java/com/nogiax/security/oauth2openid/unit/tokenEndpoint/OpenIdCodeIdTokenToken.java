package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

/**
 * Created by Xorpherion on 12.02.2017.
 */
public class OpenIdCodeIdTokenToken extends BaseOpenIdTokenEndpointTests<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken> {
    @Override
    protected Class<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken> getPreClass() {
        return com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken.class;
    }
}
