package com.nogiax.security.oauth2openid.server.endpoints;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Parameters {

    public static Map<String, String> stripEmptyParams(Map<String, String> params) {
        HashMap<String, String> result = new HashMap<>(params);
        for (String key : result.keySet())
            if (result.get(key).isEmpty())
                result.remove(key);
        return result;
    }

    public static boolean redirectUriIsAbsolute(String redirectUri) {
        try {
            URI uri = new URI(redirectUri);
            return uri.isAbsolute();
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
