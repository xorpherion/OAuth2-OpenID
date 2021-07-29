package com.bornium.security.oauth2openid.unit.tokenEndpoint;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.token.IdTokenVerifier;
import com.bornium.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 12.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCodeIdTokenToken")
public class OpenIdCodeIdTokenToken extends BaseOpenIdTokenEndpointTests<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken> {
    @Override
    protected Class<com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken> getPreClass() {
        return com.bornium.security.oauth2openid.unit.authorizationEndpoint.OpenIdCodeIdTokenToken.class;
    }

    public OpenIdCodeIdTokenToken() {
        additionalValidation = new Consumer<Exchange>() {
            @Override
            public void accept(Exchange exc) {
                try {
                    String jwk = server.getTokenManager().getJwk();
                    IdTokenVerifier verifier = new IdTokenVerifier(jwk);
                    String idToken = Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ID_TOKEN);
                    String accessToken = Common.getBodyParamsFromResponse(exc).get(Constants.PARAMETER_ACCESS_TOKEN);
                    Map<String, String> claims = verifier.verifyAndGetClaims(idToken, server.getProvidedServices().getIssuer(), getClientId());

                    assertEquals(ConstantsTest.CLIENT_DEFAULT_NONCE, claims.get(Constants.PARAMETER_NONCE));
                    assertEquals(Util.halfHashFromValue(Constants.ALG_SHA_256, accessToken), claims.get(Constants.CLAIM_AT_HASH));
                    assertEquals(ConstantsTest.CUSTOM_CLAIM_VALUE, claims.get(ConstantsTest.CUSTOM_CLAIM_NAME));
                } catch (Exception e) {
                    assertEquals(1, 0, e.getMessage());
                }
            }
        };
    }
}
