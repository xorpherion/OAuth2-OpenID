package com.nogiax.security.oauth2openid;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public interface Session {

    String getValue(String key) throws Exception;

    void putValue(String key, String value) throws Exception;

    void removeValue(String sessionRedirectFromError) throws Exception;
}
