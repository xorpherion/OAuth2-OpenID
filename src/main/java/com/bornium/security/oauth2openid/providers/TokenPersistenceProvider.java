package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.token.Token;
import com.bornium.security.oauth2openid.token.TokenManager;

import java.time.Duration;
import java.time.LocalDateTime;

public interface TokenPersistenceProvider {
    /**
     * Creates a new token.
     *
     * <b>The new token is not yet stored.</b> A token can be stored
     * <ul>
     *     <li>by calling <code>tokenManager.addToken(...)</code> on one of the tokenManagers (returned by {@link #createTokenManager(String)}) or</li>
     *     <li>by calling <code>token.addChild(...)</code> on another token.</li>
     * </ul>
     */
    Token createToken(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri, String nonce);

    /**
     * @param tokenManagerId a unique string identifying this TokenManager instance within the persistenceProvider
     */
    TokenManager createTokenManager(String tokenManagerId);
}
