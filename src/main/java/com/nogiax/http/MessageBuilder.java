package com.nogiax.http;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MessageBuilder<T extends Message, S extends MessageBuilder<T, S>> {

    T message;

    public MessageBuilder(T message) {
        this.message = message;
    }

    public S header(String name, String value) {
        message.getHeader().append(name, value);
        return (S) this;
    }

    public S body(String body) {
        message.setBody(body);
        return (S) this;
    }

    public T build() {
        return message;
    }
}
