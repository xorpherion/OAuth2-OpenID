package com.bornium.security.oauth2openid.providers;

public class NonSpecConfiguration {

    boolean issueIdTokenInResourceOwnerPasswordCredentialsGrant;
    boolean issueIdTokenInClientCredentialsGrant;
    boolean issueRefreshTokenInClientCredentialsGrant;

    public NonSpecConfiguration() {
        this(false,false,false);
    }

    public NonSpecConfiguration(boolean issueIdTokenInResourceOwnerPasswordCredentialsGrant, boolean issueIdTokenInClientCredentialsGrant, boolean issueRefreshTokenInClientCredentialsGrant) {
        this.issueIdTokenInResourceOwnerPasswordCredentialsGrant = issueIdTokenInResourceOwnerPasswordCredentialsGrant;
        this.issueIdTokenInClientCredentialsGrant = issueIdTokenInClientCredentialsGrant;
        this.issueRefreshTokenInClientCredentialsGrant = issueRefreshTokenInClientCredentialsGrant;
    }

    public boolean isIssueIdTokenInResourceOwnerPasswordCredentialsGrant() {
        return issueIdTokenInResourceOwnerPasswordCredentialsGrant;
    }

    public boolean isIssueIdTokenInClientCredentialsGrant() {
        return issueIdTokenInClientCredentialsGrant;
    }

    public boolean isIssueRefreshTokenInClientCredentialsGrant() {
        return issueRefreshTokenInClientCredentialsGrant;
    }
}
