package com.nogiax.security.oauth2openid.server.endpoints;

import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerServices;
import com.nogiax.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Created by Xorpherion on 31.01.2017.
 */
public class UserinfoEndpoint extends Endpoint {
    public UserinfoEndpoint(ServerServices serverServices) {
        super(serverServices, Constants.ENDPOINT_USERINFO);
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        log.info("Userinfo endpoint");
        if (!exc.getRequest().getHeader().getRawHeaders().containsKey(Constants.HEADER_AUTHORIZATION)) {
            exc.setResponse(this.answerWithBody(401, ""));
            exc.getResponse().getHeader().append(Constants.HEADER_WWW_AUTHENTICATE, "Bearer realm=\"token\"");
            return;
        }
        String[] authHeader = exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION).split(Pattern.quote(" "));
        if (!Constants.PARAMETER_VALUE_BEARER.equals(authHeader[0])) {
            exc.setResponse(this.answerWithError(400, Constants.ERROR_INVALID_REQUEST));
            return;
        }

        String accessTokenValue = authHeader[1];

        if (!serverServices.getTokenManager().getAccessTokens().tokenExists(accessTokenValue)) {
            exc.setResponse(this.answerWithError(401, Constants.ERROR_INVALID_TOKEN));
            return;
        }

        Token accessToken = serverServices.getTokenManager().getAccessTokens().getToken(accessTokenValue);
        if (accessToken.isExpired()) {
            exc.setResponse(this.answerWithError(401, Constants.ERROR_INVALID_TOKEN));
            return;
        }
        HashMap<String, String> resp = new HashMap<>();
        resp.put("Message", "Success");
        exc.setResponse(okWithJSONBody(resp));
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
