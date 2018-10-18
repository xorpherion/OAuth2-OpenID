package com.bornium.security.oauth2openid;

import java.util.HashMap;

/**
 * Created by Xorpherion on 27.01.2017.
 */
public class UserMembrane {

    String name;
    String password;

    HashMap<String, String> claims;

    public UserMembrane(String name, String password) {
        this.name = name;
        this.password = password;

        claims = new HashMap<>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public HashMap<String, String> getClaims() {
        return claims;
    }

    public void setClaims(HashMap<String, String> claims) {
        this.claims = claims;
    }
}
