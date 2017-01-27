package com.nogiax.security.oauth2openid.providers;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public interface ClientDataProvider {
    boolean clientExists(String clientId);
}
