package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Created by Xorpherion on 08.02.2017.
 */
public class JwkEndpoint extends Endpoint {

    String jwk;

    public JwkEndpoint(AuthorizationServer serverServices) throws JsonProcessingException {
        super(serverServices, Constants.ENDPOINT_JWK);
//        ArrayList<String> keys = new ArrayList<>();
//        keys.add(serverServices.getTokenManager().getJwk());
//        HashMap<String,String> keysMap = new HashMap<>();
//        keysMap.put("keys",new ObjectMapper().writeValueAsString(keys));
//        jwk = new ObjectMapper().writeValueAsString(keysMap);
        jwk = serverServices.getTokenManager().getJwk();
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {

        exc.setResponse(new ResponseBuilder().statuscode(200).body(jwk).build());
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }
}
