package com.bornium.security.oauth2openid.token;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface Token {
    void revokeCascade();
    void addChild(Token child);
    void incrementUsage();
    boolean isExpired();
    String getValue();
    String getUsername();
    String getClientId();
    LocalDateTime getIssued();
    Duration getValidFor();
    String getClaims();
    ArrayList<Token> getChildren();
    int getUsages();
    String getScope();
    boolean isManuallyRevoked();
    String getRedirectUri();
    String getNonce();
}
