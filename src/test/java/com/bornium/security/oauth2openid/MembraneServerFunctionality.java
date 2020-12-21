package com.bornium.security.oauth2openid;

import com.bornium.security.oauth2openid.provider.*;
import com.bornium.security.oauth2openid.providers.*;
import com.bornium.security.oauth2openid.server.EndpointFactory;
import com.bornium.security.oauth2openid.server.ProvidedServices;
import com.bornium.impl.LoginEndpoint;
import com.bornium.impl.BearerTokenProvider;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneServerFunctionality implements ProvidedServices {

    private final String issuer;
    private final MembraneGrantContextProvider grantContextDaoProvider;
    private final MembraneConsentProvider consentProvider;
    MembraneSessionProvider sessionProvider;
    MembraneClientDataProvider clientDataProvider;
    MembraneUserDataProvider userDataProvider;
    MembraneTokenPersistenceProvider tokenPersistenceProvider;
    TimingProvider timingProvider;
    TokenProvider tokenProvider;

    public MembraneServerFunctionality(String issuer) {
        sessionProvider = new MembraneSessionProvider("SC_ID");
        clientDataProvider = new MembraneClientDataProvider();
        userDataProvider = new MembraneUserDataProvider();
        tokenPersistenceProvider = new MembraneTokenPersistenceProvider();
        timingProvider = new DefaultTimingProvider();
        tokenProvider = new BearerTokenProvider();
        grantContextDaoProvider = new MembraneGrantContextProvider();
        consentProvider = new MembraneConsentProvider();
        this.issuer = issuer;
    }

    @Override
    public ConsentProvider getConsentProvider() {
        return consentProvider;
    }

    @Override
    public GrantContextProvider getGrantContextProvider() {
        return grantContextDaoProvider;
    }

    @Override
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }

    @Override
    public ClientDataProvider getClientDataProvider() {
        return clientDataProvider;
    }

    @Override
    public UserDataProvider getUserDataProvider() {
        return userDataProvider;
    }

    @Override
    public TokenPersistenceProvider getTokenPersistenceProvider() {
        return tokenPersistenceProvider;
    }

    @Override
    public TimingProvider getTimingProvider() {
        return timingProvider;
    }

    @Override
    public TokenProvider getTokenProvider() {
        return tokenProvider;
    }

    @Override
    public ConfigProvider getConfigProvider() {
        return null;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public Set<String> getSupportedClaims() {
        HashSet<String> result = new HashSet<>();
        result.add(ConstantsTest.CUSTOM_CLAIM_NAME);
        return result;
    }

    @Override
    public String getContextPath() {
        return "";
    }

    @Override
    public String getSubClaimName() {
        return "username";
    }

    @Override
    public EndpointFactory getEndpointFactory() {
        return serverServices -> new LoginEndpoint(serverServices);
    }
}
