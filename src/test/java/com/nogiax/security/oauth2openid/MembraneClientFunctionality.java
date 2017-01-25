package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.providers.HttpClientProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneClientFunctionality implements ClientProvider {
    @Override
    public HttpClientProvider getHttpClient() {
        return null;
    }
}
