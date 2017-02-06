package com.nogiax.security.oauth2openid.providers;

import java.util.Map;
import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface UserDataProvider {
    boolean verifyUser(String username, String plaintextPassword);

    Map<String,String> getClaims(String username, Set<String> claims);
    String getSubClaim(String username);
}
