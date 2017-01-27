package com.nogiax.security.oauth2openid.provider;

import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.User;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.providers.UserDataProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 27.01.2017.
 */
public class MembraneUserDataProvider implements UserDataProvider {

    Map<String,User> users;

    public MembraneUserDataProvider() {
        this.users = new HashMap<>();
        users.put(ConstantsTest.USER_DEFAULT_NAME, Util.createDefaultUser());
    }

    @Override
    public boolean verifyUser(String username, String secret) {
        if(!users.containsKey(username))
            return false;
        User user = users.get(username);
        if(!secret.equals(user.getPassword()))
            return false;
        return true;
    }
}
