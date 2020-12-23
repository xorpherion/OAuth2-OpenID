package com.bornium.impl;

import com.bornium.security.oauth2openid.providers.LoginResult;

import java.util.function.Consumer;

public class LoginResultWithCallback {

    String grantContextId;
    LoginResult accumulator;
    Consumer<LoginResult> callback;
    boolean skipConsentCheck;

    public LoginResultWithCallback(String grantContextId, boolean skipConsentCheck, LoginResult accumulator, Consumer<LoginResult> callback) {
        this.grantContextId = grantContextId;
        this.skipConsentCheck = skipConsentCheck;
        this.accumulator = accumulator;
        this.callback = callback;
    }

    public String getGrantContextId() {
        return grantContextId;
    }

    public LoginResult getAccumulator() {
        return accumulator;
    }

    public Consumer<LoginResult> getCallback() {
        return callback;
    }

    public boolean isSkipConsentCheck() {
        return skipConsentCheck;
    }
}
