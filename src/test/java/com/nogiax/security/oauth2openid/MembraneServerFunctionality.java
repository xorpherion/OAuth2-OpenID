package com.nogiax.security.oauth2openid;

import com.nogiax.security.oauth2openid.provider.MembraneClientDataProvider;
import com.nogiax.security.oauth2openid.provider.MembraneSessionProvider;
import com.nogiax.security.oauth2openid.provider.MembraneUserDataProvider;
import com.nogiax.security.oauth2openid.providers.ClientDataProvider;
import com.nogiax.security.oauth2openid.providers.SessionProvider;
import com.nogiax.security.oauth2openid.providers.UserDataProvider;
import com.nogiax.security.oauth2openid.server.ProvidedServices;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class MembraneServerFunctionality implements ProvidedServices {

    private final String issuer;
    MembraneSessionProvider sessionProvider;
    MembraneClientDataProvider clientDataProvider;
    MembraneUserDataProvider userDataProvider;

    public MembraneServerFunctionality(String issuer) {
        sessionProvider = new MembraneSessionProvider("SC_ID");
        clientDataProvider = new MembraneClientDataProvider();
        userDataProvider = new MembraneUserDataProvider();
        this.issuer = issuer;
    }

    @Override
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }

    @Override
    public ClientDataProvider getClientDataProvider() {
        return clientDataProvider;
    }

    @Override
    public UserDataProvider getUserDataProvider() {
        return userDataProvider;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public Set<String> getSupportedClaims() {
        HashSet<String> result = new HashSet<>();
        result.add(ConstantsTest.CUSTOM_CLAIM_NAME);
        return result;
    }
}
