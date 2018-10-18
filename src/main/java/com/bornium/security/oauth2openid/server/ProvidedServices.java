package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.providers.ClientDataProvider;
import com.bornium.security.oauth2openid.providers.SessionProvider;
import com.bornium.security.oauth2openid.providers.UserDataProvider;

import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface ProvidedServices {

    SessionProvider getSessionProvider();

    ClientDataProvider getClientDataProvider();

    UserDataProvider getUserDataProvider();

    String getIssuer();

    Set<String> getSupportedClaims();

    String getContextPath();
}
