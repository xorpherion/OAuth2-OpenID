package com.nogiax.http;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class ResponseBuilder extends MessageBuilder<Response, ResponseBuilder> {

    public ResponseBuilder() {
        this(new Response());
    }

    public ResponseBuilder(Response message) {
        super(message == null ? new Response() : message);
    }

    public ResponseBuilder statuscode(int code) {
        message.setStatuscode(code);
        return this;
    }

    public ResponseBuilder redirectTemp(String uri) {
        return statuscode(307).header("Location", uri);
    }

    public Exchange buildExchange() {
        return new Exchange(build());
    }

    public Exchange buildExchange(Request req) {
        return new Exchange(req, build());
    }
}
