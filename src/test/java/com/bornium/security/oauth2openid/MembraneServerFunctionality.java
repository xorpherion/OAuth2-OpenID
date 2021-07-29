package com.bornium.security.oauth2openid;

import com.bornium.security.oauth2openid.provider.*;
import com.bornium.security.oauth2openid.providers.*;
import com.bornium.security.oauth2openid.server.EndpointFactory;
import com.bornium.security.oauth2openid.server.ProvidedServices;
import com.bornium.impl.LoginEndpoint;
import com.bornium.impl.BearerTokenProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneServerFunctionality implements ProvidedServices {

    private final String issuer;
    private final MembraneGrantContextProvider grantContextDaoProvider;
    private final MembraneConsentProvider consentProvider;
    private final MembraneConfigProvider membraneConfigProvider;
    private final MembraneAuthenticationProvider membraneAuthenticationProvider;
    MembraneSessionProvider sessionProvider;
    MembraneClientDataProvider clientDataProvider;
    MembraneUserDataProvider userDataProvider;
    MembraneTokenPersistenceProvider tokenPersistenceProvider;
    TimingProvider timingProvider;
    TokenProvider tokenProvider;


    public MembraneServerFunctionality(String issuer) {
        this(issuer,new MembraneGrantContextProvider(), new MembraneConsentProvider(),new MembraneConfigProvider(), new MembraneSessionProvider("SC_ID"), new MembraneClientDataProvider(), new MembraneUserDataProvider(), new MembraneTokenPersistenceProvider(), new DefaultTimingProvider(), new BearerTokenProvider(), new MembraneAuthenticationProvider());
    }

    public MembraneServerFunctionality(String issuer, MembraneGrantContextProvider grantContextDaoProvider, MembraneConsentProvider consentProvider, MembraneConfigProvider membraneConfigProvider, MembraneSessionProvider sessionProvider, MembraneClientDataProvider clientDataProvider, MembraneUserDataProvider userDataProvider, MembraneTokenPersistenceProvider tokenPersistenceProvider, TimingProvider timingProvider, TokenProvider tokenProvider, MembraneAuthenticationProvider membraneAuthenticationProvider) {
        this.issuer = issuer;
        this.grantContextDaoProvider = grantContextDaoProvider;
        this.consentProvider = consentProvider;
        this.membraneConfigProvider = membraneConfigProvider;
        this.sessionProvider = sessionProvider;
        this.clientDataProvider = clientDataProvider;
        this.userDataProvider = userDataProvider;
        this.tokenPersistenceProvider = tokenPersistenceProvider;
        this.timingProvider = timingProvider;
        this.tokenProvider = tokenProvider;
        this.membraneAuthenticationProvider = membraneAuthenticationProvider;

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
        return membraneConfigProvider;
    }

    @Override
    public String getIssuer() {
        return issuer;
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

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return membraneAuthenticationProvider;
    }
}
