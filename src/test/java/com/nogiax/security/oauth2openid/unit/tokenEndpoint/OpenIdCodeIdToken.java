package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

/**
 * Created by Xorpherion on 12.02.2017.
 */
public class OpenIdCodeIdToken extends BaseOpenIdTokenEndpointTests<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken> {
    @Override
    protected Class<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken> getPreClass() {
        return com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdToken.class;
    }
}