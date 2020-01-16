package com.bornium.security.oauth2openid.token;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryTokenManager extends TokenManager {

    //@GuardedBy("this")
    private final HashMap<String, Token> activeTokens;
    //@GuardedBy("this")
    private final HashMap<String, Token> inactiveTokens;

    public InMemoryTokenManager() {
        activeTokens = new HashMap<>();
        inactiveTokens = new HashMap<>();
    }

    private Map<String, Token> selectCorrectMap(Token token) {
        if (!token.isExpired())
            return activeTokens;
        return inactiveTokens;
    }

    public synchronized void addToken(Token token) {
        deactivateExpiredTokens();
        selectCorrectMap(token).put(token.getValue(), token);
    }

    protected Map<String, Token> tokenExistsInMapElseNull(String token) {
        if (activeTokens.containsKey(token))
            return activeTokens;
        if (inactiveTokens.containsKey(token))
            return inactiveTokens;
        return null;
    }

    protected void deactivateExpiredTokens() {
        List<String> toRemove = new ArrayList<>();
        for (String val : activeTokens.keySet())
            if (activeTokens.get(val).isExpired()) {
                toRemove.add(val);
            }
        toRemove.stream().forEach(val -> {
            expireToken(val);
        });
    }

    protected void expireToken(String value) {
        inactiveTokens.put(value, activeTokens.get(value));
        activeTokens.remove(value);
    }

    public synchronized boolean tokenExists(String token) {
        return tokenExistsInMapElseNull(token) != null;
    }

    public synchronized Token getToken(String value) {
        deactivateExpiredTokens();
        Map<String, Token> stringTokenMap = tokenExistsInMapElseNull(value);
        if(stringTokenMap == null)
            return null;
        return stringTokenMap.get(value);
    }

}
