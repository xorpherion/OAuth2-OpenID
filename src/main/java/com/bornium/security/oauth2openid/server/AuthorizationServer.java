package com.bornium.security.oauth2openid.server;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.impl.VerificationEndpoint;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.permissions.Scope;
import com.bornium.security.oauth2openid.server.endpoints.*;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginEndpointBase;
import com.bornium.security.oauth2openid.token.CombinedTokenManager;
import com.bornium.security.oauth2openid.token.IdTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class AuthorizationServer {
    Logger LOG = LoggerFactory.getLogger(AuthorizationServer.class);

    ArrayList<Endpoint> endpoints;
    ProvidedServices providedServices;
    CombinedTokenManager tokenManager;
    SupportedScopes supportedScopes;
    SupportedClaims supportedClaims;
    LoginEndpointBase loginEndpoint;

    public AuthorizationServer(ProvidedServices providedServices) throws Exception {
        this(providedServices, new IdTokenProvider());
    }

    public AuthorizationServer(ProvidedServices providedServices, IdTokenProvider idTokenProvider) throws Exception {
        this.providedServices = providedServices;
        this.tokenManager = new CombinedTokenManager(idTokenProvider, providedServices.getTokenProvider(), providedServices.getTokenPersistenceProvider(), providedServices.getTimingProvider());
        this.supportedScopes = new SupportedScopes(defaultScopes());
        this.supportedClaims = new SupportedClaims(supportedClaims());

        for (String claim : providedServices.getSupportedClaims())
            this.supportedClaims.addValidClaim(claim);

        endpoints = new ArrayList<>();

        endpoints.add(new AuthorizationEndpoint(this));
        endpoints.add(new DeviceAuthorizationEndpoint(this));
        endpoints.add(new TokenEndpoint(this));
        endpoints.add(new UserinfoEndpoint(this));
        endpoints.add(new RevocationEndpoint(this));
        endpoints.add(new JwkEndpoint(this));
        endpoints.add(new WellKnownEndpoint(this));
        endpoints.add(new VerificationEndpoint(this));

        WrappedLoginEndpoint loginEndpointToBeAdded = new WrappedLoginEndpoint(providedServices.getEndpointFactory().createLogin(this), providedServices.getUserDataProvider(), providedServices.getGrantContextProvider());
        loginEndpoint = loginEndpointToBeAdded.getLoginEndpoint();

        endpoints.add(loginEndpointToBeAdded);
    }

    public Exchange invokeOn(Exchange exc) throws Exception {
        //log.info("Authorization server connect");
        for (Endpoint endpoint : endpoints)
            if (exc.getResponse() == null)
                endpoint.useIfResponsible(exc);
        if (exc.getResponse() == null)
            exc.setResponse(new ResponseBuilder().statuscode(404).body("Not found - try /userinfo with access token in Authorization Header").build());
        addMissingHeaders(exc);
        return exc;
    }

    private void addMissingHeaders(Exchange exc) {
        if (exc != null && exc.getResponse() != null) {
            exc.getResponse().getHeader().append(Constants.HEADER_CACHE_CONTROL, Constants.HEADER_VALUE_NO_STORE);
            exc.getResponse().getHeader().append(Constants.HEADER_PRAGMA, Constants.HEADER_VALUE_NO_CACHE);
            exc.getResponse().getHeader().append(Constants.HEADER_X_FRAME_OPTIONS, Constants.HEADER_VALUE_SAMEORIGIN);
            if(exc.getResponse().getStatuscode() == 401)
                exc.getResponse().getHeader().add("WWW-Authenticate","Bearer realm=\"OAuth2\"");
        }
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

    public ArrayList<Endpoint> getEndpoints() {
        return endpoints;
    }

    public LoginEndpointBase getLoginEndpoint() {
        return loginEndpoint;
    }
}
