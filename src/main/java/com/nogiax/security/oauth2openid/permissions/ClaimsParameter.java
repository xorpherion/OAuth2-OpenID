package com.nogiax.security.oauth2openid.permissions;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by Xorpherion on 06.02.2017.
 */
public class ClaimsParameter {

    Map<String, Object> claimsParam;

    public ClaimsParameter(String claimsParameter) throws IOException {
        if (claimsParameter != null)
            claimsParam = new ObjectMapper().readValue(claimsParameter, Map.class);
    }

    public HashSet<String> getAllClaimNames() {
        return new HashSet<>();
    }
}
