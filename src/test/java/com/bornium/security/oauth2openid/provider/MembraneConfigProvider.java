package com.bornium.security.oauth2openid.provider;

import com.bornium.security.oauth2openid.permissions.Scope;
import com.bornium.security.oauth2openid.providers.ActiveGrantsConfiguration;
import com.bornium.security.oauth2openid.providers.ConfigProvider;
import com.bornium.security.oauth2openid.providers.NonSpecConfiguration;
import com.bornium.security.oauth2openid.server.TokenContext;

import java.util.List;
import java.util.Set;

public class MembraneConfigProvider implements ConfigProvider {

    private ActiveGrantsConfiguration activeGrantsConfiguration;

    public MembraneConfigProvider() {
        activeGrantsConfiguration = new ActiveGrantsConfiguration();
    }

    @Override
    public boolean useReusableRefreshTokens(TokenContext tokenContext) {
        return false;
    }

    @Override
    public ActiveGrantsConfiguration getActiveGrantsConfiguration() {
        return activeGrantsConfiguration;
    }

    @Override
    public boolean disableNonRecommendedGrants() {
        return false;
    }

    @Override
    public List<Scope> getSupportedScopes(List<Scope> defaultProvided) {
        return defaultProvided;
    }

    @Override
    public Set<String> getSupportedClaims(Set<String> defaultProvided) {
        return defaultProvided;
    }

    @Override
    public NonSpecConfiguration getNonSpecConfiguration() {
        return new NonSpecConfiguration();
    }
}
