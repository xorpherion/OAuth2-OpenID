package com.nogiax.security.oauth2openid.provider;

import com.nogiax.security.oauth2openid.Client;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.Util;
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
        clients.put(ConstantsTest.CLIENT_DEFAULT_ID, Util.createDefaultClient());
    }

    @Override
    public boolean clientExists(String clientId) {
        return clients.containsKey(clientId);
    }
}
