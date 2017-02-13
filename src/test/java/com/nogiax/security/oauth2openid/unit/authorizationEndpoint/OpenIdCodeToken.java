package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;

import java.net.URI;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 09.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCodeToken")
public class OpenIdCodeToken extends BaseOpenIdAuthorizationEndpointTests {
    @Override
    public String getResponseType() {
        return Constants.TOKEN_TYPE_CODE + " " + Constants.TOKEN_TYPE_TOKEN;
    }

    @Override
    public String getScope() {
        return ConstantsTest.CLIENT_DEFAULT_SCOPE_OPENID;
    }

    @Override
    public String getResponseMode() {
        return null;
    }

    @Override
    public String getNonce() {
        return ConstantsTest.CLIENT_DEFAULT_NONCE;
    }

    @Override
    public String getPrompt() {
        return null;
    }

    @Override
    public String getMaxAge() {
        return null;
    }

    @Override
    public String getIdTokenHint() {
        return null;
    }

    @Override
    public String getLoginHint() {
        return null;
    }

    @Override
    public String getAuthenticationContextClass() {
        return null;
    }

    @Override
    public String getClaims() {
        return null;
    }

    @Override
    public boolean isImplicit() {
        return true;
    }

    @Override
    public Consumer<Exchange> validateResultPostLogin() {
        return exc -> assertAll(
                Common.getMethodName(),
                () -> assertEquals(303, exc.getResponse().getStatuscode()),
                () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_CODE)),
                () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ACCESS_TOKEN)),
                () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_EXPIRES_IN)),
                () -> assertNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ID_TOKEN)),
                () -> assertEquals(ConstantsTest.CLIENT_DEFAULT_STATE, Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_STATE))
        );
    }
}
