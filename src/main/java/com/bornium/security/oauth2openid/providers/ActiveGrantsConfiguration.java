package com.bornium.security.oauth2openid.providers;

public class ActiveGrantsConfiguration {

    boolean authorizationCode;
    boolean implicit;
    boolean resourceOwnerPasswordCredentials;
    boolean clientCredentials;
    boolean refreshToken;
    boolean deviceAuthorization;
    boolean revocation;

    public ActiveGrantsConfiguration(boolean authorizationCode, boolean implicit, boolean resourceOwnerPasswordCredentials, boolean clientCredentials, boolean refreshToken, boolean deviceAuthorization, boolean revocation) {
        this.authorizationCode = authorizationCode;
        this.implicit = implicit;
        this.resourceOwnerPasswordCredentials = resourceOwnerPasswordCredentials;
        this.clientCredentials = clientCredentials;
        this.refreshToken = refreshToken;
        this.deviceAuthorization = deviceAuthorization;
        this.revocation = revocation;
    }

    public ActiveGrantsConfiguration(){
        this(true,true,true,true,true,true,true);
    }

    public boolean isAuthorizationCode() {
        return authorizationCode;
    }

    public boolean isImplicit() {
        return implicit;
    }

    public boolean isResourceOwnerPasswordCredentials() {
        return resourceOwnerPasswordCredentials;
    }

    public boolean isClientCredentials() {
        return clientCredentials;
    }

    public boolean isRefreshToken() {
        return refreshToken;
    }

    public boolean isDeviceAuthorization() {
        return deviceAuthorization;
    }

    public boolean isRevocation() {
        return revocation;
    }

    public ActiveGrantsConfiguration disableNonRecommendedGrants() {
        return new ActiveGrantsConfiguration(authorizationCode, false, false, clientCredentials, refreshToken, deviceAuthorization, revocation);
    }
}
