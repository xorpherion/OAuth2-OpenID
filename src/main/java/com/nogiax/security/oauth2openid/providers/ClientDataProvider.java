package com.nogiax.security.oauth2openid.providers;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public interface ClientDataProvider {
    boolean clientExists(String clientId);

    boolean verify(String clientId, String secret);

    String getRedirectUri(String clientId);
}
