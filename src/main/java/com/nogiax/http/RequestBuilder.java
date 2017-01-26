package com.nogiax.http;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class RequestBuilder extends MessageBuilder<Request, RequestBuilder> {

    public RequestBuilder() {
        this(new Request());
    }

    public RequestBuilder(Request message) {
        super(message == null ? new Request() : message);
    }

    public RequestBuilder method(String method) {
        method(Method.fromString(method));
        return this;
    }

    public RequestBuilder method(Method method) {
        message.setMethod(method);
        return this;
    }

    public RequestBuilder uri(String uri) throws URISyntaxException {
        return uri(new URI(uri));
    }

    public RequestBuilder uri(URI uri) {
        message.setUri(uri);
        return this;
    }

    public Exchange buildExchange() {
        return new Exchange(build());
    }

    public Exchange buildExchange(Response resp) {
        return new Exchange(build(), resp);
    }
}
