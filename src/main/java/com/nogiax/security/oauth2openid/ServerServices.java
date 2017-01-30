package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.token.CombinedTokenManager;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class ServerServices {
    ProvidedServices providedServices;
    CombinedTokenManager tokenManager;

    public ServerServices(ProvidedServices providedServices) {
        this.providedServices = providedServices;
        this.tokenManager = new CombinedTokenManager();
    }

    public ProvidedServices getProvidedServices() {
        return providedServices;
    }

    public CombinedTokenManager getTokenManager() {
        return tokenManager;
    }
}
