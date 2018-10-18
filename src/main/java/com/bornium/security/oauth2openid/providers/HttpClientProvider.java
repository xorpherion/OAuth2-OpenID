package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public interface HttpClientProvider {

    Exchange sendExchange(Exchange exc) throws Exception;
}
