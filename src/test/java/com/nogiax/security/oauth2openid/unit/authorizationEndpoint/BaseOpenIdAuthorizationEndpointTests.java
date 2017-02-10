package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;

import java.util.function.Consumer;

/**
 * Created by Xorpherion on 09.02.2017.
 */
public abstract class BaseOpenIdAuthorizationEndpointTests extends BaseAuthorizationEndpointTests {

    public abstract String getResponseMode();
    public abstract String getNonce();
    public abstract String getPrompt();
    public abstract String getMaxAge();
    public abstract String getIdTokenHint();
    public abstract String getLoginHint();
    public abstract String getAuthenticationContextClass();
    public abstract String getClaims();
    public abstract boolean isImplicit();

    @Override
    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    @Override
    public String getRedirectUri() {
        return ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI;
    }

    @Override
    public String getState() {
        return ConstantsTest.CLIENT_DEFAULT_STATE;
    }
}
