package com.nogiax.http;

import java.io.IOException;
import java.net.URI;

/**
 * Created by Xorpherion on 17.08.2016.
 */
public class Request extends Message {

    private Method method;
    private URI uri;

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public URI getUri() {
        return uri;
    }

    public void setUri(URI uri) {
        this.uri = uri;
    }
}
