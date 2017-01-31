package com.nogiax.security.oauth2openid.provider;

import com.nogiax.security.oauth2openid.Client;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.UtilMembrane;
import com.nogiax.security.oauth2openid.providers.ClientDataProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MembraneClientDataProvider implements ClientDataProvider {

    Map<String, Client> clients;

    public MembraneClientDataProvider() {
        clients = new HashMap<>();
        clients.put(ConstantsTest.CLIENT_DEFAULT_ID, UtilMembrane.createDefaultClient());
    }

    @Override
    public boolean clientExists(String clientId) {
        return clients.containsKey(clientId);
    }

    @Override
    public boolean verify(String clientId, String secret) {
        if (!clientExists(clientId))
            return false;
        Client client = clients.get(clientId);
        return client.getClientSecret().equals(secret);

    }

    @Override
    public String getRedirectUri(String clientId) {
        return clients.get(clientId).getRedirectUri();
    }
}
