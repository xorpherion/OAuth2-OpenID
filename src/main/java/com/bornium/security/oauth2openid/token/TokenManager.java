package com.bornium.security.oauth2openid.token;

import java.util.HashMap;

/**
 * Created by Xorpherion on 28.01.2017.
 */
public abstract class TokenManager {

    /**
     * Add a token to the store.
     */
    public abstract void addToken(Token token);

    /**
     * @return true, iff the token exists
     */
    public abstract boolean tokenExists(String token);

    /**
     * @return a token from the store, based on its value. Returns null, iff no such token exists in the store.
     */
    public abstract Token getToken(String value);
}
