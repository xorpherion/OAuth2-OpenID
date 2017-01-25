package com.nogiax.security.oauth2openid.token;

import java.util.HashMap;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class TokenManager {

    private final BearerTokenProvider tokenProvider;
    private final HashMap<String,Token> activeTokens;

    public TokenManager(){
        tokenProvider = new BearerTokenProvider();
        activeTokens = new HashMap<>();
    }



}
