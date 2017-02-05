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

    public static Map<String,String> createParams(String... tuples){
        if(tuples.length % 2 != 0)
            throw new IllegalArgumentException("Argument needs to be tuples of key/value");
        Map<String,String> result = new HashMap<>();
        for(int i = 0; i < tuples.length; i+=2)
            result.put(tuples[i],tuples[i+1]);
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
