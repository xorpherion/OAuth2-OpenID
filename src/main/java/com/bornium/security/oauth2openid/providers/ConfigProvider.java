package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.server.TokenContext;

public interface ConfigProvider {

    boolean useReusableRefreshTokens(TokenContext tokenContext);

}
