package com.bornium.http.util;

import com.bornium.security.oauth2openid.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class UriUtil {
    static Logger log = LoggerFactory.getLogger(UriUtil.class);

    public static String encode(String str) throws UnsupportedEncodingException {
        return URLEncoder.encode(str, Constants.ENCODING_DEFAULT);
    }

    public static String decode(String str) throws UnsupportedEncodingException {
        return URLDecoder.decode(str, Constants.ENCODING_DEFAULT);
    }

    public static String parametersToQuery(Map<String, String> parameters) {
        StringBuilder result = new StringBuilder();

        if (parameters == null || parameters.isEmpty())
            return result.toString();

        for (String paramName : parameters.keySet())
            try {
                result.append(encode(paramName)).append("=").append(encode(parameters.get(paramName))).append("&");
            } catch (UnsupportedEncodingException e) {
                // should never throw because it is the default encoding of the JVM
                log.error("Default encoding was unsupported");
            }
        result.deleteCharAt(result.length() - 1);

        return result.toString();
    }

    public static Map<String, String> queryToParameters(String query) {
        HashMap<String, String> result = new HashMap<>();

        if (query == null || query.isEmpty())
            return result;

        String[] paramsRaw = query.split(Pattern.quote("&"));
        for (String paramRaw : paramsRaw) {
            String[] paramSplit = paramRaw.split(Pattern.quote("="));
            try {
                result.put(decode(paramSplit[0]), decode(paramSplit[1]));
            } catch (UnsupportedEncodingException e) {
                // should never throw because it is the default encoding of the JVM
                log.error("Default encoding was unsupported");
            }
        }

        return result;
    }
}
