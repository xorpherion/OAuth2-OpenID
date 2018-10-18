package com.bornium.security.oauth2openid.providers;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public interface Session {

    String getValue(String key) throws Exception;

    void putValue(String key, String value) throws Exception;

    void removeValue(String key) throws Exception;

    void clear() throws Exception;
}
