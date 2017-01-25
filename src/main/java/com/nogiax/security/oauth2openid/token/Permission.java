package com.nogiax.security.oauth2openid.token;

import java.util.HashMap;
import java.util.HashSet;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Permission {
    HashSet<String> scopes;
    HashMap<String,Claim> claims;
}
