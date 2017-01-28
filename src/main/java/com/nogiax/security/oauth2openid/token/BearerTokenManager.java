package com.nogiax.security.oauth2openid.token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public class BearerTokenManager {

    private final HashMap<String, Token> activeTokens;
    private final HashMap<String, Token> inactiveTokens;

    public BearerTokenManager() {
        activeTokens = new HashMap<>();
        inactiveTokens = new HashMap<>();
    }

    public Map<String,Token> tokenExistsInMapElseNull(String token){
        if(activeTokens.containsKey(token))
            return activeTokens;
        if(inactiveTokens.containsKey(token))
            return inactiveTokens;
        return null;
    }

    private void deactivateExpiredTokens(){
        for(String val : activeTokens.keySet())
            if(activeTokens.get(val).isExpired()){
                expireToken(val);
            }
    }

    private Map<String,Token> selectCorrectMap(Token token){
        if(!token.isExpired())
            return activeTokens;
        return inactiveTokens;
    }

    public void addToken(Token token){
        deactivateExpiredTokens();
        selectCorrectMap(token).put(token.getValue(),token);
    }

    public boolean tokenExists(String token){

        return tokenExistsInMapElseNull(token) != null;
    }

    public Token getToken(String value){
        deactivateExpiredTokens();
        return tokenExistsInMapElseNull(value).get(value);
    }

    public void expireToken(String value){
        inactiveTokens.put(value,activeTokens.get(value));
        activeTokens.remove(value);
    }
}
