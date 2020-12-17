package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;

import java.util.Map;
import java.util.Set;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface UserDataProvider {
    boolean verifyUser(String username, String password); // needed for resource owner password credentials flow and default login implementation

    Map<String, Object> getClaims(String username, Set<String> claims);

    String getSubClaim(String username);
}
