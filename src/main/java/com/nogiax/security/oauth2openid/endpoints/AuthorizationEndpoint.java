package com.nogiax.security.oauth2openid.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.FixedNames;
import com.nogiax.security.oauth2openid.ProvidedFuntionality;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationEndpoint extends Endpoint{
    private final ProvidedFuntionality functionality;

    public AuthorizationEndpoint(ProvidedFuntionality functionality) {
        super(FixedNames.ENDPOINT_AUTHORIZATION);
        this.functionality = functionality;
    }

    @Override
    public boolean invokeOnOAuth2(Exchange exc) {
        return false;
    }

    @Override
    public boolean invokeOnOpenId(Exchange exc) {
        return false;
    }

    @Override
    public String getScope(Exchange exc) {
        return null;
    }
}
