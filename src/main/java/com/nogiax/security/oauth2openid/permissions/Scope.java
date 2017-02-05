package com.nogiax.security.oauth2openid.permissions;

import java.util.HashSet;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class Scope {

    String name;
    HashSet<String> claims;

    public Scope(String name, String... claims) {
        this.name = name;
        this.claims = new HashSet<>();

        for(String claim : claims)
            this.claims.add(claim);
    }

    public String getName() {
        return name;
    }

    public HashSet<String> getClaims() {
        return claims;
    }
}
