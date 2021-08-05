package com.bornium.security.oauth2openid.providers;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public abstract class GrantContext {

    public static final String IDENTIFIER_KEY_NAME = "_IDENTIFIER";

    public abstract String getValue(String key);

    public abstract void putValue(String key, String value);

    public abstract Map<String,String> all();

    public abstract void removeValue(String key);

    public abstract void clear();

    @JsonIgnore
    public String getIdentifier() {
        return getValue(IDENTIFIER_KEY_NAME);
    }

    @JsonIgnore
    public void setIdentifier(String identifier) {
        putValue(IDENTIFIER_KEY_NAME,identifier);
    }
}
