package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.providers.ClientDataProvider;
import com.nogiax.security.oauth2openid.providers.SessionProvider;
import com.nogiax.security.oauth2openid.providers.UserDataProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface ProvidedServices {

    SessionProvider getSessionProvider();

    ClientDataProvider getClientDataProvider();

    UserDataProvider getUserDataProvider();

    String getIssuer();
}
