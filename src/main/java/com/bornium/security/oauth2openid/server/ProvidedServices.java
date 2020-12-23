package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.providers.*;

import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface ProvidedServices {

    ConsentProvider getConsentProvider();

    GrantContextProvider getGrantContextProvider();

    SessionProvider getSessionProvider();

    ClientDataProvider getClientDataProvider();

    UserDataProvider getUserDataProvider();

    TokenPersistenceProvider getTokenPersistenceProvider();

    TimingProvider getTimingProvider();

    TokenProvider getTokenProvider();

    ConfigProvider getConfigProvider();

    String getIssuer();

    String getContextPath();

    String getSubClaimName();

    EndpointFactory getEndpointFactory();

    AuthenticationProvider getAuthenticationProvider();
}
