package com.bornium.security.oauth2openid.unit.authorizationEndpoint;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.Util;
import com.bornium.security.oauth2openid.token.IdTokenVerifier;
import com.bornium.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.DisplayName;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by Xorpherion on 09.02.2017.
 */
@DisplayName("AuthorizationEndpoint.OpenIdCodeIdTokenToken")
public class OpenIdCodeIdTokenToken extends BaseOpenIdAuthorizationEndpointTests {

    @Override
    public String getResponseType() {
        return Constants.TOKEN_TYPE_CODE + " " + Constants.TOKEN_TYPE_ID_TOKEN + " " + Constants.TOKEN_TYPE_TOKEN;
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
        Map<String, Object> json = new HashMap<String, Object>();
        Map<String, String> idTokenClaims = new HashMap<>();
        json.put(Constants.PARAMETER_ID_TOKEN, idTokenClaims);

        idTokenClaims.put(ConstantsTest.CUSTOM_CLAIM_NAME, null);
        try {
            return new ObjectMapper().writeValueAsString(json);
        } catch (JsonProcessingException e) {
            throw new RuntimeException();
        }
    }

    @Override
    public boolean isImplicit() {
        return true;
    }

    @Override
    public Consumer<Exchange> validateResultPostLogin() {
        return exc -> {
            assertAll(
                    Common.getMethodName(),
                    () -> assertEquals(303, exc.getResponse().getStatuscode()),
                    () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_CODE)),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ACCESS_TOKEN)),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_EXPIRES_IN)),
                    () -> assertNotNull(Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ID_TOKEN)),
                    () -> assertEquals(ConstantsTest.CLIENT_DEFAULT_STATE, Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_STATE))
            );
            try {
                String jwk = server.getTokenManager().getJwk();
                IdTokenVerifier verifier = new IdTokenVerifier(jwk);
                String idToken = Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ID_TOKEN);
                String accessToken = Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_ACCESS_TOKEN);
                String code = Common.getParamsFromRedirectResponse(exc, isImplicit()).get(Constants.PARAMETER_CODE);
                Map<String, String> claims = verifier.verifyAndGetClaims(idToken, server.getProvidedServices().getIssuer(), getClientId());

                assertEquals(getNonce(), claims.get(Constants.PARAMETER_NONCE));
                assertEquals(Util.halfHashFromValue(Constants.ALG_SHA_256, accessToken), claims.get(Constants.CLAIM_AT_HASH));
                assertEquals(Util.halfHashFromValue(Constants.ALG_SHA_256, code), claims.get(Constants.CLAIM_C_HASH));
                assertEquals(ConstantsTest.CUSTOM_CLAIM_VALUE, claims.get(ConstantsTest.CUSTOM_CLAIM_NAME));
            } catch (Exception e) {
                assertEquals(1, 0, e.getMessage());
            }


        };
    }
}
