package com.nogiax.security.oauth2openid.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.FixedNames;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public abstract class Endpoint {

    String path;

    public Endpoint(String path){
        this.path = path;
    }

    public void useIfResponsible(Exchange exc){
        if(isResponsible(exc))
            invokeOn(exc);
    }

    public boolean isResponsible(Exchange exc){
        return exc.getRequest().getUri().getPath().endsWith(path);
    }

    public boolean invokeOn(Exchange exc){
        if(invokeOnOAuth2(exc))
            if(hasOpenIdScope(getScope(exc)))
                if(invokeOnOpenId(exc))
                    return true;
        return false;
    }

    public abstract boolean invokeOnOAuth2(Exchange exc);

    public abstract boolean invokeOnOpenId(Exchange exc);

    public abstract String getScope(Exchange exc);

    private boolean hasOpenIdScope(String scope){
        return scope.contains(FixedNames.SCOPE_OPENID);
    }
}
