package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.server.TokenContext;

public interface TokenProvider {
    String get(TokenContext tokenContext);
}
