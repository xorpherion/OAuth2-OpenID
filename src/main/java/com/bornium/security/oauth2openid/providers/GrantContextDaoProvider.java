package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;

import java.util.Optional;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public abstract class GrantContextDaoProvider {

    public abstract GrantContext create();
    public abstract void persist(GrantContext ctx);

    /**
     * It is possible that (e.g. due to a bug or not having all identifiers in all situations for a GrantContext) this method is not called for all identifiers that exist.
     * GrantContexts are short lived objects ( lifetime is one active oauth2 grant execution, ~ 60 seconds max?).
     * Your implementation should have a TTL on all identifiers by default
     * @param identifier
     */
    public abstract void invalidate(String... identifier);

    /**
     * find by identifier
     * @param identifier can be null
     * @return Empty if not found
     */
    public abstract Optional<GrantContext> findById(String identifier);

    public GrantContext findByIdOrCreate(String identifier){
        Optional<GrantContext> ctx = findById(identifier);
        if(!ctx.isPresent())
            return create();

        return ctx.get();
    }
}
