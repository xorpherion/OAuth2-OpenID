package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.Response;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.server.ServerServices;
import com.bornium.security.oauth2openid.token.Token;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
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
        //log.info("Userinfo endpoint");
        if (exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION) == null) {
            exc.setResponse(this.answerWithBody(401, "", ""));
            exc.getResponse().getHeader().append(Constants.HEADER_WWW_AUTHENTICATE, "Bearer realm=\"token\"");
            return;
        }
        String[] authHeader = exc.getRequest().getHeader().getValue(Constants.HEADER_AUTHORIZATION).split(Pattern.quote(" "));
        if (authHeader.length != 2) {
            exc.setResponse(this.answerWithError(401, Constants.ERROR_INVALID_TOKEN));
            return;
        }
        if (!Constants.PARAMETER_VALUE_BEARER.equals(authHeader[0])) {
            exc.setResponse(this.answerWithError(401, Constants.ERROR_INVALID_TOKEN));
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
        HashMap<String, Object> resp = new HashMap<>();
        Set<String> claims = getValidUserinfoClaimsFromToken(accessToken);
        claims.add(serverServices.getProvidedServices().getSubClaimName());

        Map<String, Object> claimValues = serverServices.getProvidedServices().getUserDataProvider().getClaims(accessToken.getUsername(), claims);
        claimValues = Parameters.stripNullParams(claimValues);

        resp.putAll(claimValues);
        exc.setResponse(okWithJSONBody(resp));
    }

    private Response createErrorResponse(String error){
        Response res = this.answerWithBody(401, "", "");
        res.getHeader().append(Constants.HEADER_WWW_AUTHENTICATE, "Bearer realm=\"token\", error=" + error);
        return res;
    }
    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
