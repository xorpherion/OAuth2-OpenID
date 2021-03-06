package com.bornium.http;

import com.bornium.security.oauth2openid.Constants;

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

    public ResponseBuilder redirectTempWithGet(String uri) {
        return statuscode(303).header(Constants.HEADER_LOCATION, uri);
    }

    public ResponseBuilder redirectTempIdentical(String uri) {
        return statuscode(307).header(Constants.HEADER_LOCATION, uri);
    }

    public Exchange buildExchange() {
        return new Exchange(build());
    }

    public Exchange buildExchange(Request req) {
        return new Exchange(req, build());
    }
}
