package com.nogiax.security.oauth2openid.token;

import com.nogiax.security.oauth2openid.User;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.Period;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Token {

    static Duration defaultValidFor = Duration.ofMinutes(10);

    String token;
    User recipient;
    LocalDateTime issued;
    LocalDateTime expires;
    String scopes;
    String claims;

    public Token(String token, User recipient, LocalDateTime issued, Duration validFor) {
        this.token = token;
        this.recipient = recipient;
        this.issued = issued;
        this.expires = issued.plus(validFor);
    }

    public Token(String token, User recipient, Duration validFor) {
        this(token,recipient,LocalDateTime.now(),validFor);
    }

    public Token(String token, User recipient){
        this(token,recipient,defaultValidFor);
    }

    public boolean isRecipientValid(String username, String secret){
        return username.equals(recipient.getName()) && secret.equals(recipient.getSecret());
    }

    public boolean isExpired(){
        return LocalDateTime.now().isAfter(expires);
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public User getRecipient() {
        return recipient;
    }

    public void setRecipient(User recipient) {
        this.recipient = recipient;
    }

    public LocalDateTime getIssued() {
        return issued;
    }

    public void setIssued(LocalDateTime issued) {
        this.issued = issued;
    }

    public LocalDateTime getExpires() {
        return expires;
    }

    public void setExpires(LocalDateTime expires) {
        this.expires = expires;
    }
}
