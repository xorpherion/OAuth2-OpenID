package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.model.WellKnown;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class WellKnownEndpoint extends Endpoint {

    WellKnown wellKnown;
    String issuer;

    public WellKnownEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_WELL_KNOWN);
        issuer = serverServices.getProvidedServices().getIssuer();
        wellKnown = new WellKnown(issuer,
                path(Constants.ENDPOINT_AUTHORIZATION),
                path(Constants.ENDPOINT_DEVICE_AUTHORIZATION),
                path(Constants.ENDPOINT_TOKEN),
                path(Constants.ENDPOINT_USERINFO),
                path(Constants.ENDPOINT_REVOCATION),
                path(Constants.ENDPOINT_JWK),
                getSupportedResponseTypes(),
                getSupportedGrantTypes(),
                getSubjectTypesSupported(),
                getIdTokenSigningAlgValuesSupported(),
                serverServices.getSupportedScopes().getSupportedScopes().keySet().stream().collect(Collectors.toList()),
                getTokenEndpointAuthMethodsSupported(),
                serverServices.getSupportedClaims().getClaims().stream().collect(Collectors.toList()),
                getCodeChallengeMethodsSupported()
        );
    }

    private List<String> getSupportedGrantTypes() {
        return Arrays.asList(
                "implicit",
                "authorization_code",
                "refresh_token",
                "password",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code"
        );
    }

    // PKCE - not yet implemented
    private List<String> getCodeChallengeMethodsSupported() {
        return null;
    }

    private List<String> getTokenEndpointAuthMethodsSupported() {
        return Arrays.asList(
                "client_secret_post",
                "client_secret_basic"
        );
    }

    private List<String> getIdTokenSigningAlgValuesSupported() {
        return Arrays.asList(
                serverServices.getTokenManager().getIdTokenProvider().getRsaJsonWebKey().getAlgorithm()
        );
    }

    private List<String> getSubjectTypesSupported() {
        return Arrays.asList(
                "public"
        );
    }

    private List<String> getSupportedResponseTypes() {
        return Arrays.asList(
                "code",
                "code id_token",
                "code id_token token",
                "code token",
                "id_token",
                "id_token token",
                "token"
        );
    }

    public String path(String suffix){
        return issuer + suffix;
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        exc.setResponse(new ResponseBuilder().statuscode(200).body(new ObjectMapper().writeValueAsString(wellKnown)).build());
    }

    @Override
    public String getScope(Exchange exc){
        return "openid";
    }
}
