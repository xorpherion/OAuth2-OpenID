package com.bornium.security.oauth2openid.server;

import com.bornium.security.oauth2openid.permissions.Scope;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 04.02.2017.
 */
public class SupportedScopes {

    Map<String, Scope> supportedScopes;

    public SupportedScopes(Scope... supportedScopes) {
        this.supportedScopes = new HashMap<>();

        for (Scope scope : supportedScopes)
            this.supportedScopes.put(scope.getName(), scope);
    }

    public boolean scopesSupported(String scopes) {
        if (scopes == null || scopes.isEmpty())
            return false;
        String[] scopesArr = scopes.split(Pattern.quote(" "));
        for (String scope : scopesArr)
            if (!this.supportedScopes.containsKey(scope))
                return false;
        return true;
    }

    public Set<String> getClaimsForScope(String scope) {
        HashSet<String> result = new HashSet<>();

        for (String s : scope.split(Pattern.quote(" ")))
            result.addAll(supportedScopes.get(s).getClaims());

        return result;
    }

    public Map<String, Scope> getSupportedScopes() {
        return supportedScopes;
    }
}
