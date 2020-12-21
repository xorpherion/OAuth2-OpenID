package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.GrantContextProvider;
import com.bornium.security.oauth2openid.providers.UserDataProvider;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginEndpointBase;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginResult;

import java.util.Optional;

public class WrappedLoginEndpoint extends WrappedEndpoint<LoginEndpointBase>{
    private UserDataProvider userDataProvider;
    private GrantContextProvider sessionProvider;

    public WrappedLoginEndpoint(LoginEndpointBase toBeWrapped, UserDataProvider userDataProvider, GrantContextProvider sessionProvider) {
        super(toBeWrapped);
        this.userDataProvider = userDataProvider;
        this.sessionProvider = sessionProvider;
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        super.invokeOn(exc);

        String grantContextId = toBeWrapped.getGrantContextId(exc);

        if(grantContextId == null)
            return;

        LoginResult res = toBeWrapped.getCurrentResultFor(grantContextId);
        GrantContext ctx = sessionProvider.findById(grantContextId).get();

        Optional<String> maybeUser = res.getAuthenticatedUser();

        if(!maybeUser.isPresent())
            return;

        ctx.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);
        ctx.putValue(Constants.LOGIN_USERNAME, res.getAuthenticatedUser().get());

        toBeWrapped.serverServices.getProvidedServices().getGrantContextProvider().persist(ctx);
    }

    public LoginEndpointBase getLoginEndpoint(){
        return toBeWrapped;
    }
}
