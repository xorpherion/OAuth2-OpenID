package com.nogiax.http;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Exchange {
    private Request request;

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

    private Response response;

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
    }
}
