package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.provider.MembraneClientDataProvider;
import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.nogiax.security.oauth2openid.providers.ClientDataProvider;
import com.nogiax.security.oauth2openid.providers.SessionProvider;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneServerFunctionality implements ServerProvider {

    MembraneSessionProvider sessionProvider;
    MembraneClientDataProvider clientDataProvider;

    public MembraneServerFunctionality(){
        sessionProvider = new MembraneSessionProvider("SC_ID");
        clientDataProvider = new MembraneClientDataProvider();
    }

    @Override
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }

    @Override
    public ClientDataProvider getClientDataProvider() {
        return clientDataProvider;
    }
}
