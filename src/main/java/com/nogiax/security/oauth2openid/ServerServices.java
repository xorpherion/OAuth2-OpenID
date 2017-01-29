package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.token.AllTokenManager;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class ServerServices {
    ProvidedServices providedServices;
    AllTokenManager tokenManager;

    public ServerServices(ProvidedServices providedServices) {
        this.providedServices = providedServices;
        this.tokenManager = new AllTokenManager();
    }

    public ProvidedServices getProvidedServices() {
        return providedServices;
    }

    public AllTokenManager getTokenManager() {
        return tokenManager;
    }
}
