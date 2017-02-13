package com.nogiax.security.oauth2openid.provider;

import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.UserMembrane;
import com.nogiax.security.oauth2openid.UtilMembrane;
import com.nogiax.security.oauth2openid.providers.UserDataProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by Xorpherion on 27.01.2017.
 */
public class MembraneUserDataProvider implements UserDataProvider {

    Map<String, UserMembrane> users;

    public MembraneUserDataProvider() {
        this.users = new HashMap<>();
        users.put(ConstantsTest.USER_DEFAULT_NAME, UtilMembrane.createDefaultUser());
    }

    @Override
    public boolean verifyUser(String username, String secret) {
        if (!users.containsKey(username))
            return false;
        UserMembrane user = users.get(username);
        return secret.equals(user.getPassword());

    }

    @Override
    public Map<String, String> getClaims(String username, Set<String> claims) {
        HashMap<String, String> result = new HashMap<>();
        if (users.containsKey(username))
            for (String claim : claims)
                result.put(claim, users.get(username).getClaims().get(claim));
        return result;
    }

    @Override
    public String getSubClaim(String username) {
        if (!users.containsKey(username))
            return "N/A";
        return users.get(username).getClaims().get(Constants.CLAIM_SUB);
    }

    @Override
    public void badLogin(String username) {
        if(users.containsKey(username))
            System.out.println("Bad login for " + username + ". Sending email to user.");
    }
}
