package com.bornium.security.oauth2openid.permissions;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class ClaimsParameter {

    Map<String, Object> userinfo;
    Map<String, Object> id_token;

    public ClaimsParameter(String claimsParameter) throws IOException {
        if (claimsParameter != null) {
            Map<String, Object> claims = new ObjectMapper().readValue(claimsParameter, Map.class);
            userinfo = (Map<String, Object>) claims.get("userinfo");
            id_token = (Map<String, Object>) claims.get("id_token");
        }
    }

    public Set<String> getAllUserinfoClaimNames() {
        Set<String> result = new HashSet<>();
        if (userinfo != null)
            result.addAll(userinfo.keySet());
        return result;
    }

    public Set<String> getAllIdTokenClaimNames() {
        Set<String> result = new HashSet<>();
        if (id_token != null)
            result.addAll(id_token.keySet());
        return result;
    }
}
