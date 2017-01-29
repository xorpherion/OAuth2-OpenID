package com.nogiax.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Token {

    static Duration defaultValidFor = Duration.ofMinutes(10);

    private final String value;
    private final String username;
    private final String clientId;
    private final LocalDateTime issued;
    private final Duration validFor;
    private final String claims;
    private final Token[] children;
    private int usages;

    public Token(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, Token... children) {
        this.value = value;
        this.username = username;
        this.clientId = clientId;
        this.issued = issued;
        this.validFor = validFor;
        this.claims = claims;
        this.children = children;
        usages = 0;
    }

    public void incrementUsage(){
        usages++;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(LocalDateTime.now().plus(validFor));
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

    public Token[] getChildren() {
        return children;
    }

    public int getUsages() {
        return usages;
    }
}
