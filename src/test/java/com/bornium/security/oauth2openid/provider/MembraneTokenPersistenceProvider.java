package com.bornium.security.oauth2openid.provider;

import com.bornium.security.oauth2openid.providers.TokenPersistenceProvider;
import com.bornium.security.oauth2openid.token.InMemoryTokenManager;
import com.bornium.security.oauth2openid.token.Token;
import com.bornium.security.oauth2openid.token.TokenManager;

import java.time.Duration;
import java.time.LocalDateTime;

public class MembraneTokenPersistenceProvider implements TokenPersistenceProvider {
    public static class InMemoryToken extends Token {
        public InMemoryToken(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri, Token... children) {
            super(value, username, clientId, issued, validFor, claims, scope, redirectUri, children);
        }
    }

    @Override
    public Token createToken(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri) {
        return new InMemoryToken(value, username, clientId, issued, validFor, claims, scope, redirectUri);
    }

    @Override
    public TokenManager createTokenManager(String tokenManagerId) {
        return new InMemoryTokenManager();
    }
}
