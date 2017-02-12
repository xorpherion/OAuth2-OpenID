package com.nogiax.security.oauth2openid.unit.tokenEndpoint;

import com.nogiax.http.Exchange;
import org.junit.jupiter.api.DisplayName;

import java.util.function.Supplier;

/**
 * Created by Xorpherion on 12.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCode")
public class OpenIdCode extends BaseOpenIdTokenEndpointTests<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode> {
    @Override
    protected Class<com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode> getPreClass() {
        return com.nogiax.security.oauth2openid.unit.authorizationEndpoint.OpenIdCode.class;
    }
}
