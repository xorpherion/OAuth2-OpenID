package com.nogiax.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Exchange {

    private Request request;
    private Response response;
    private Map<String, Object> properties;


    public Exchange() {
        this(null, null);
    }

    public Exchange(Request request) {
        this(request, null);
    }

    public Exchange(Response response) {
        this(null, response);
    }

    public Exchange(Request request, Response response) {
        this.request = request;
        this.response = response;

        properties = new HashMap<>();
    }

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public Response getResponse() {
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return this.getClass().getName();
        }
    }
}
