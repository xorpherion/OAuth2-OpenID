package com.nogiax.security.oauth2openid.server;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class SupportedClaims {

    HashSet<String> claims;

    public SupportedClaims(String... claims) {
        this.claims = new HashSet<String>();

        for (String claim : claims)
            this.claims.add(claim);
    }

    public Set<String> getValidClaims(Set<String> claims) {
        HashSet<String> result = new HashSet<>();
        for (String claim : claims)
            if (this.claims.contains(claim))
                result.add(claim);
        return result;
    }
}
