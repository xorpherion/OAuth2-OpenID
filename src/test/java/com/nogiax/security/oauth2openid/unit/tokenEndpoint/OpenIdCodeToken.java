package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

/**
 * Created by Xorpherion on 12.02.2017.
 */
public class OpenIdCodeToken extends BaseOpenIdTokenEndpointTests<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken> {
    @Override
    protected Class<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken> getPreClass() {
        return com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeToken.class;
    }
}
