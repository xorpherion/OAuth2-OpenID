package com.nogiax.http;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public enum Method {
    GET,
    POST,
    PUT,
    DELETE;

    public static Method fromString(String method) {
        switch (method.toUpperCase()) {
            case "GET":
                return Method.GET;
            case "POST":
                return Method.POST;
            case "PUT":
                return Method.PUT;
            case "DELETE":
                return Method.DELETE;
        }
        throw new IllegalArgumentException("Method not supported");
    }

    public static String toString(Method method) {
        switch (method) {
            case GET:
                return "GET";
            case POST:
                return "POST";
            case PUT:
                return "PUT";
            case DELETE:
                return "DELETE";
        }
        throw new IllegalArgumentException("Method not supported");
    }

    @Override
    public String toString(){
        return toString(this);
    }
}
