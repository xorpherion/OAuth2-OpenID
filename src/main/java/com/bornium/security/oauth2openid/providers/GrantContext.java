package com.bornium.security.oauth2openid.providers;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public abstract class GrantContext {

    protected String identifier;

    public abstract String getValue(String key) throws Exception;

    public abstract void putValue(String key, String value) throws Exception;

    public abstract void removeValue(String key) throws Exception;

    public abstract void clear() throws Exception;

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
