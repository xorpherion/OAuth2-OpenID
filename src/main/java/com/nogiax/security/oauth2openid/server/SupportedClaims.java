package com.nogiax.security.oauth2openid.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class SupportedClaims {

    HashSet<String> claims;

    public SupportedClaims(String... claims){
        this.claims = new HashSet<String>();

        for(String claim : claims)
            this.claims.add(claim);
    }

    public boolean claimsSupported(String claims) throws IOException {
        return claimsSupported(new ObjectMapper().readValue(claims, Map.class));
    }

    public boolean claimsSupported(Map<String,Object> json){
        throw new RuntimeException("NYI");
    }

}
