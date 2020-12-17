package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.GrantContextDaoProvider;
import com.bornium.security.oauth2openid.providers.UserDataProvider;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginEndpointBase;
import com.bornium.security.oauth2openid.server.endpoints.login.LoginResult;

import java.util.Optional;

public class WrappedLoginEndpoint extends WrappedEndpoint<LoginEndpointBase>{
    private UserDataProvider userDataProvider;
    private GrantContextDaoProvider sessionProvider;

    public WrappedLoginEndpoint(LoginEndpointBase toBeWrapped, UserDataProvider userDataProvider, GrantContextDaoProvider sessionProvider) {
        super(toBeWrapped);
        this.userDataProvider = userDataProvider;
        this.sessionProvider = sessionProvider;
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        super.invokeOn(exc);

        String grantContextId = toBeWrapped.getGrantContextId(exc);

        LoginResult res = toBeWrapped.getCurrentResultFor(grantContextId);
        GrantContext session = sessionProvider.findById(grantContextId).get();

        Optional<String> maybeUser = res.getAuthenticatedUser();

        if(!maybeUser.isPresent())
            return;

        session.putValue(Constants.SESSION_LOGGED_IN, Constants.VALUE_YES);

        if(!res.hasConsented())
            return;

        session.putValue(Constants.SESSION_CONSENT_GIVEN, Constants.VALUE_YES);
    }

    public LoginEndpointBase getLoginEndpoint(){
        return toBeWrapped;
    }
}
