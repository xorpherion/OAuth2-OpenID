package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.providers.*;

import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface ProvidedServices {

    SessionProvider getSessionProvider();

    ClientDataProvider getClientDataProvider();

    UserDataProvider getUserDataProvider();

    TokenPersistenceProvider getTokenPersistenceProvider();

    TimingProvider getTimingProvider();

    TokenProvider getTokenProvider();

    String getIssuer();

    Set<String> getSupportedClaims();

    String getContextPath();

    String getSubClaimName();
}
