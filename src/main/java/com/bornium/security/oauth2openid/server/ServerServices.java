package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.permissions.Scope;
import com.bornium.security.oauth2openid.token.CombinedTokenManager;
import com.bornium.security.oauth2openid.token.IdTokenProvider;
import org.jose4j.lang.JoseException;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class ServerServices {
    ProvidedServices providedServices;
    CombinedTokenManager tokenManager;
    SupportedScopes supportedScopes;
    SupportedClaims supportedClaims;

    public ServerServices(ProvidedServices providedServices) throws JoseException {
        this(providedServices, new IdTokenProvider());
    }

    public ServerServices(ProvidedServices providedServices, IdTokenProvider idTokenProvider) {
        this.providedServices = providedServices;
        this.tokenManager = new CombinedTokenManager(idTokenProvider, providedServices.getTokenProvider(), providedServices.getTokenPersistenceProvider(), providedServices.getTimingProvider());
        this.supportedScopes = new SupportedScopes(defaultScopes());
        this.supportedClaims = new SupportedClaims(supportedClaims());

        for (String claim : providedServices.getSupportedClaims())
            this.supportedClaims.addValidClaim(claim);
    }

    private Scope[] defaultScopes() {
        return new Scope[]{
                new Scope(Constants.SCOPE_OPENID, Constants.CLAIM_SUB),
                new Scope(Constants.SCOPE_PROFILE, Constants.CLAIM_NAME, Constants.CLAIM_FAMILY_NAME, Constants.CLAIM_GIVEN_NAME,
                        Constants.CLAIM_MIDDLE_NAME, Constants.CLAIM_NICKNAME, Constants.CLAIM_PREFERRED_USERNAME,
                        Constants.CLAIM_PROFILE, Constants.CLAIM_PICTURE, Constants.CLAIM_WEBSITE, Constants.CLAIM_GENDER,
                        Constants.CLAIM_BIRTHDATE, Constants.CLAIM_ZONEINFO, Constants.CLAIM_LOCALE, Constants.CLAIM_UPDATED_AT),
                new Scope(Constants.SCOPE_EMAIL, Constants.CLAIM_EMAIL, Constants.CLAIM_EMAIL_VERIFIED),
                new Scope(Constants.SCOPE_ADDRESS, Constants.CLAIM_ADDRESS),
                new Scope(Constants.SCOPE_PHONE, Constants.CLAIM_PHONE_NUMBER, Constants.CLAIM_PHONE_NUMBER_VERIFIED)
        };
    }

    private String[] supportedClaims() {
        return new String[]{Constants.CLAIM_SUB, Constants.CLAIM_NAME, Constants.CLAIM_GIVEN_NAME, Constants.CLAIM_FAMILY_NAME, Constants.CLAIM_MIDDLE_NAME, Constants.CLAIM_NICKNAME, Constants.CLAIM_PREFERRED_USERNAME,
                Constants.CLAIM_PROFILE, Constants.CLAIM_PICTURE, Constants.CLAIM_WEBSITE, Constants.CLAIM_EMAIL, Constants.CLAIM_EMAIL_VERIFIED, Constants.CLAIM_GENDER, Constants.CLAIM_BIRTHDATE, Constants.CLAIM_ZONEINFO, Constants.CLAIM_LOCALE,
                Constants.CLAIM_PHONE_NUMBER, Constants.CLAIM_PHONE_NUMBER_VERIFIED, Constants.CLAIM_ADDRESS, Constants.CLAIM_UPDATED_AT};
    }

    public ProvidedServices getProvidedServices() {
        return providedServices;
    }

    public CombinedTokenManager getTokenManager() {
        return tokenManager;
    }

    public SupportedScopes getSupportedScopes() {
        return supportedScopes;
    }

    public SupportedClaims getSupportedClaims() {
        return supportedClaims;
    }
}
