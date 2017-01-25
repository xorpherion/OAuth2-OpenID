package com.nogiax.http;

import java.io.IOException;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Response extends Message {

    private int statuscode = 200;

    public int getStatuscode() {
        return statuscode;
    }

    public void setStatuscode(int statuscode) {
        this.statuscode = statuscode;
    }

}
