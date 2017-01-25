package com.nogiax.security.oauth2openid;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class User {

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    String name;
    String secret;
}
