package com.bornium.security.oauth2openid.provider;

import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.GrantContextDaoProvider;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.providers.SessionProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Convert;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.predic8.membrane.core.interceptor.authentication.session.SessionManager;
import com.predic8.membrane.core.rules.NullRule;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MembraneGrantContextDaoProvider extends GrantContextDaoProvider {

    Cache<String,GrantContext> ctxs = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    @Override
    public GrantContext create() {
        return new GrantContext() {

            Map<String,String> state = new HashMap<>();

            @Override
            public String getValue(String key) throws Exception {
                return state.get(key);
            }

            @Override
            public void putValue(String key, String value) throws Exception {
                state.put(key,value);
            }

            @Override
            public Set<String> allKeys() throws Exception {
                return state.keySet();
            }

            @Override
            public void removeValue(String key) throws Exception {
                state.remove(key);
            }

            @Override
            public void clear() throws Exception {
                state.clear();
            }
        };
    }

    @Override
    public void persist(GrantContext ctx) {
        ctxs.put(ctx.getIdentifier(), ctx);
    }


    @Override
    public void invalidationHint(String... identifiers) {
        Arrays.stream(identifiers).forEach(id -> ctxs.invalidate(id));
    }

    @Override
    public Optional<GrantContext> findById(String identifier) {
        if(identifier == null)
            return Optional.empty();

        return Optional.ofNullable(ctxs.getIfPresent(identifier));
    }
}
