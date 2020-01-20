package com.bornium.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public abstract class Token {

    static Duration defaultValidFor = Duration.ofMinutes(10);
    static Duration defaultValidForLong = Duration.ofDays(1);

    private final String value;
    private final String username;
    private final String clientId;
    private final LocalDateTime issued;
    private final Duration validFor;
    private final String claims;
    private final String scope;
    private final String redirectUri;
    private final ArrayList<Token> children;
    private int usages;
    private boolean manuallyRevoked;

    public Token(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri, Token... children) {
        this.value = value;
        this.username = username;
        this.clientId = clientId;
        this.issued = issued;
        this.validFor = validFor;
        this.claims = claims;
        this.scope = scope;
        this.redirectUri = redirectUri;
        synchronized (this) {
            this.children = new ArrayList<>();
            Collections.addAll(this.children, children);
            usages = 0;
            manuallyRevoked = false;
        }
    }

    public synchronized void revokeCascade() {
        manuallyRevoked = true;
        for (Token t : children)
            t.revokeCascade();
    }

    public synchronized void addChild(Token child) {
        children.add(child);
    }

    public synchronized void incrementUsage() {
        usages++;
    }

    public synchronized boolean isExpired() {
        return LocalDateTime.now().isAfter(LocalDateTime.now().plus(validFor)) || manuallyRevoked;
    }

    public static Duration getDefaultValidFor() {
        return defaultValidFor;
    }

    public String getValue() {
        return value;
    }

    public String getUsername() {
        return username;
    }

    public String getClientId() {
        return clientId;
    }

    public LocalDateTime getIssued() {
        return issued;
    }

    public Duration getValidFor() {
        return validFor;
    }

    public String getClaims() {
        return claims;
    }

    public synchronized ArrayList getChildren() {
        return children;
    }

    public synchronized int getUsages() {
        return usages;
    }

    public static Duration getDefaultValidForLong() {
        return defaultValidForLong;
    }

    public String getScope() {
        return scope;
    }

    public synchronized boolean isManuallyRevoked() {
        return manuallyRevoked;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

}
