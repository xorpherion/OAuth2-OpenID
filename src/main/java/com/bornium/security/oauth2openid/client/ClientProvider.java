package com.bornium.security.oauth2openid.client;

import com.bornium.security.oauth2openid.providers.HttpClientProvider;
import com.bornium.security.oauth2openid.providers.SessionProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface ClientProvider {

    HttpClientProvider getHttpClient();

    SessionProvider getSessionProvider();
}
