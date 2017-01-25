package com.nogiax.http;

import java.io.IOException;

/**
 * Created by Xorpherion on 17.08.2016.
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
