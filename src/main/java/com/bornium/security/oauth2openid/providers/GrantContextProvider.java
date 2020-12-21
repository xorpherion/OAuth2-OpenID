package com.bornium.security.oauth2openid.providers;

import com.bornium.http.Exchange;

import java.util.Optional;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public abstract class GrantContextProvider {

    /**
     * Creates a fresh instance
     * @return
     */
    public abstract GrantContext create();

    /**
     * store a context for later retrieval by ctx.getIdentifier().
     * GrantContexts are short lived objects that depend mostly on how fast the user can login (or authorize a device).
     * GrantContexts should not be stored indefinitely but should be either limited in count or have a TTL or both.
     * A good TTL time could be ~ 10 minutes. This should give a user enough time to complete any interaction
     * @param ctx
     */
    public abstract void persist(GrantContext ctx);

    /**
     * This server can give you a hint about GrantContexts that aren't needed anymore for early invalidation.
     * There is no requirement that this method is called for every GrantContext that was persisted.
     * GrantContexts should not be stored indefinitely but should be either limited in count or have a TTL or both.
     * @param identifier
     */
    public abstract void invalidationHint(String... identifier);

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

    public GrantContext deepCopy(GrantContext toBeCopied) throws Exception{
        GrantContext result = create();

        toBeCopied.allKeys().stream().forEach(k -> {
            try {
                result.putValue(k, toBeCopied.getValue(k));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        result.setIdentifier(toBeCopied.getIdentifier());

        return result;
    }
}
