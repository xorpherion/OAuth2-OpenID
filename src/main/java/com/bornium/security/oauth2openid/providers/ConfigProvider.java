package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.permissions.Scope;
import com.bornium.security.oauth2openid.server.TokenContext;

import java.util.List;
import java.util.Set;

public interface ConfigProvider {

    /**
     * dynamically checked on every needed occasion
     * @param tokenContext
     * @return
     */
    boolean useReusableRefreshTokens(TokenContext tokenContext);

    /**
     * not dynamic but a one time init on startup
     * @return
     */
    ActiveGrantsConfiguration getActiveGrantsConfiguration();


    /**
     *
     * @return true to disable implicit and resource owner password credentials flows
     */
    boolean disableNonRecommendedGrants();

    /**
     * not dynamic but a one time init on startup
     * @param defaultProvided default that the server supports
     * @return the final list of scopes that the server should support
     */
    List<Scope> getSupportedScopes(List<Scope> defaultProvided);

    /**
     * not dynamic but a one time init on startup
     * @param defaultProvided default that the server supports
     * @return the final list of scopes that the server should support
     */
    Set<String> getSupportedClaims(Set<String> defaultProvided);

    NonSpecConfiguration getNonSpecConfiguration();

}
