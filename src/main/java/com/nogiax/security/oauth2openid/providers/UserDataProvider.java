package com.nogiax.security.oauth2openid.providers;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface UserDataProvider {
    boolean verifyUser(String username, String secret);
}
