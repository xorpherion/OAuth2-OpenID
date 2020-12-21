package com.bornium.security.oauth2openid.providers;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public abstract class GrantContext {

    protected String identifier;

    public abstract String getValue(String key);

    public abstract void putValue(String key, String value);

    public abstract Set<String> allKeys();

    public abstract void removeValue(String key);

    public abstract void clear();

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
