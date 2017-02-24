package com.nogiax.security.oauth2openid;

import com.nogiax.http.util.UriUtil;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class Util {

    public static String encodeToBasicAuthValue(String name, String pass) throws UnsupportedEncodingException {
        return "Basic " + new String(Base64.getEncoder().encode((UriUtil.encode(name) + ":" + UriUtil.encode(pass)).getBytes()));
    }

    public static User decodeFromBasicAuthValue(String value) throws UnsupportedEncodingException {
        String[] userAndPass = new String(Base64.getDecoder().decode(value.split(Pattern.quote(" "))[1])).split(Pattern.quote(":"));
        return new User(UriUtil.decode(userAndPass[0]), UriUtil.decode(userAndPass[1]));
    }

    public static String halfHashFromValue(String alg, String accessToken) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        if (accessToken == null)
            return null;
        if (!alg.equals("SHA-256"))
            throw new RuntimeException("NYI");
        MessageDigest digest = MessageDigest.getInstance(alg);
        byte[] hash = digest.digest(accessToken.getBytes(Constants.ENCODING_DEFAULT));
        byte[] result = new byte[hash.length / 2];
        for (int i = 0; i < hash.length / 2; i++)
            result[i] = hash[i];
        return UriUtil.encode(Base64.getEncoder().encodeToString(result));
    }
}
