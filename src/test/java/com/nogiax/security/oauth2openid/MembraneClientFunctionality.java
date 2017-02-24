package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.client.ClientProvider;
import com.nogiax.security.oauth2openid.provider.MembraneHttpClientProvider;
import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.nogiax.security.oauth2openid.providers.HttpClientProvider;
import com.nogiax.security.oauth2openid.providers.SessionProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneClientFunctionality implements ClientProvider {

    MembraneSessionProvider sessionProvider;
    MembraneHttpClientProvider httpClientProvider;

    public MembraneClientFunctionality() {
        this.sessionProvider = new MembraneSessionProvider("CC_ID");
        this.httpClientProvider = new MembraneHttpClientProvider();
    }

    @Override
    public HttpClientProvider getHttpClient() {
        return httpClientProvider;
    }

    @Override
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }
}
