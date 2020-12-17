package com.bornium.impl;

import com.bornium.security.oauth2openid.providers.Session;

class DummySession implements Session {
    @Override
    public String getValue(String key) throws Exception {
        return null;
    }

    @Override
    public void putValue(String key, String value) throws Exception {

    }

    @Override
    public void removeValue(String key) throws Exception {

    }

    @Override
    public void clear() throws Exception {

    }
}
