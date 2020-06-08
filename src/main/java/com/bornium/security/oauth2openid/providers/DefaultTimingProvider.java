package com.bornium.security.oauth2openid.providers;

import com.bornium.security.oauth2openid.server.TimingContext;

import java.time.Duration;

public class DefaultTimingProvider implements TimingProvider {
    private Duration defaultValidFor = Duration.ofMinutes(10);
    private Duration defaultValidForLong = Duration.ofDays(1);

    @Override
    public Duration getShortTokenValidFor(TimingContext context) {
        return defaultValidFor;
    }

    @Override
    public Duration getRefreshTokenValidFor(TimingContext context) {
        return defaultValidForLong;
    }
}
