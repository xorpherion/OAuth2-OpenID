package com.bornium.security.oauth2openid.server.endpoints.login;

import java.util.Optional;
import java.util.Set;

public interface LoginResult {

    /**
     *
     * @return username if authenticated or empty if not
     */
    Optional<String> getAuthenticatedUser();
    boolean hasConsented();
    Set<String> acceptedScopes();
}
