package com.bornium.security.oauth2openid.providers;

import java.util.Set;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public interface ClientDataProvider {
    boolean clientExists(String clientId);

    boolean isConfidential(String clientId);

    boolean verify(String clientId, String secret);

    Set<String> getRedirectUris(String clientId);
}
