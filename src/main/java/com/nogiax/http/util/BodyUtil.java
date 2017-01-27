package com.nogiax.http.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 27.01.2017.
 */
public class BodyUtil {

    static Logger log = LoggerFactory.getLogger(BodyUtil.class);

    public static String paramsToBody(Map<String,String> parameters){
        StringBuilder result = new StringBuilder();

        if (parameters == null || parameters.isEmpty())
            return result.toString();

        for (String paramName : parameters.keySet())
            result.append(paramName).append("=").append(parameters.get(paramName)).append("&");

        result.deleteCharAt(result.length() - 1);

        return result.toString();
    }

    public static Map<String,String> bodyToParams(String body){
        HashMap<String, String> result = new HashMap<>();

        if (body == null || body.isEmpty())
            return result;

        String[] paramsRaw = body.split(Pattern.quote("&"));
        for (String paramRaw : paramsRaw) {
            String[] paramSplit = paramRaw.split(Pattern.quote("="));
            result.put(paramSplit[0], paramSplit[1]);
        }

        return result;
    }
}
