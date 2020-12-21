package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.server.ConsentContext;

import java.util.Map;
import java.util.Set;

public interface ConsentProvider {

    /**
     * apply clientId / scope tuple to username. Override old value
     */
    void persist(ConsentContext ctx);

    /**
     *
     * @param username
     * @return a mapping from clientId to given scopes for username
     */
    Map<String, ConsentContext> getConsentFor(String username);
}
