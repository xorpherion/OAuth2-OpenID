package com.bornium.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;

public abstract class InMemoryToken implements Token {

    private final String value;
    private final String username;
    private final String clientId;
    private final LocalDateTime issued;
    private final Duration validFor;
    private final String claims;
    private final String scope;
    private final String redirectUri;
    private final ArrayList<Token> children;
    private final String nonce;
    private int usages;
    private boolean manuallyRevoked;

    public InMemoryToken(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri, String nonce, Token... children) {
        this.value = value;
        this.username = username;
        this.clientId = clientId;
        this.issued = issued;
        this.validFor = validFor;
        this.claims = claims;
        this.scope = scope;
        this.redirectUri = redirectUri;
        this.nonce = nonce;
        synchronized (this) {
            this.children = new ArrayList<>();
            Collections.addAll(this.children, children);
            usages = 0;
            manuallyRevoked = false;
        }
    }

    @Override
    public synchronized void revokeCascade() {
        manuallyRevoked = true;
        for (Token t : children)
            t.revokeCascade();
    }

    @Override
    public synchronized void addChild(Token child) {
        children.add(child);
    }

    @Override
    public synchronized void incrementUsage() {
        usages++;
    }

    @Override
    public synchronized boolean isExpired() {
        return LocalDateTime.now().isAfter(LocalDateTime.now().plus(validFor)) || manuallyRevoked;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public LocalDateTime getIssued() {
        return issued;
    }

    @Override
    public Duration getValidFor() {
        return validFor;
    }

    @Override
    public String getClaims() {
        return claims;
    }

    @Override
    public synchronized ArrayList getChildren() {
        return children;
    }

    @Override
    public synchronized int getUsages() {
        return usages;
    }

    @Override
    public String getScope() {
        return scope;
    }

    @Override
    public synchronized boolean isManuallyRevoked() {
        return manuallyRevoked;
    }

    @Override
    public String getRedirectUri() {
        return redirectUri;
    }

    @Override
    public String getNonce() {
        return nonce;
    }

}
