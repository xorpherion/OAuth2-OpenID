package com.nogiax.security.oauth2openid.token;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class BearerTokenProvider {

    private final Supplier<String> factory;

    public BearerTokenProvider() {
        this.factory = new Supplier<String>() {
            private SecureRandom random = new SecureRandom();

            @Override
            public String get() {
                return getRandomBits().toString(32);
            }

            private BigInteger getRandomBits() {
                synchronized (random) {
                    return new BigInteger(130, random);
                }
            }
        };
    }

    public String get() {
        return factory.get();
    }
}
