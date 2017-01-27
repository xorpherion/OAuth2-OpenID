package com.nogiax.http;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Message {

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
