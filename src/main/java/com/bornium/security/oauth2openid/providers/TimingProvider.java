package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.server.TimingContext;

import java.time.Duration;

public interface TimingProvider {

    Duration getShortTokenValidFor(TimingContext context);

    Duration getRefreshTokenValidFor(TimingContext context);

}
