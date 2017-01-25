package com.nogiax.http;

import java.io.Closeable;
import java.io.IOException;

/**
 * Created by Xorpherion on 17.08.2016.
 */
public class Message{

    private Header header = new Header();
    private String body = "";

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }
}
