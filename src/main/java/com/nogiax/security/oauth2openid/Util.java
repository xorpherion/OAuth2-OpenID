package com.nogiax.security.oauth2openid;

import com.nogiax.http.util.UriUtil;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class Util {

    public static String encodeToBasicAuthValue(String name, String pass) throws UnsupportedEncodingException {
        return "Basic " + Base64.encode((UriUtil.encode(name) + ":" + UriUtil.encode(pass)).getBytes());
    }

    public static User decodeFromBasicAuthValue(String value) throws UnsupportedEncodingException {
        String[] userAndPass = new String(Base64.decode(value.split(Pattern.quote(" "))[1])).split(Pattern.quote(":"));
        return new User(UriUtil.decode(userAndPass[0]), UriUtil.decode(userAndPass[1]));
    }
}
