package com.bornium.security.oauth2openid.server.endpoints;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.model.WellKnown;
import com.bornium.security.oauth2openid.providers.ActiveGrantsConfiguration;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class WellKnownEndpoint extends Endpoint {

    WellKnown wellKnown;
    String issuer;

    public WellKnownEndpoint(AuthorizationServer serverServices) {
        super(serverServices, Constants.ENDPOINT_WELL_KNOWN);
        ActiveGrantsConfiguration activeGrants = serverServices.getProvidedServices().getConfigProvider().getActiveGrantsConfiguration();
        issuer = serverServices.getProvidedServices().getIssuer();
        wellKnown = new WellKnown(issuer,
                path(Constants.ENDPOINT_AUTHORIZATION),
                activeGrants.isDeviceAuthorization() ? path(Constants.ENDPOINT_DEVICE_AUTHORIZATION) : null,
                path(Constants.ENDPOINT_TOKEN),
                path(Constants.ENDPOINT_USERINFO),
                activeGrants.isRevocation() ?path(Constants.ENDPOINT_REVOCATION) : null,
                path(Constants.ENDPOINT_JWK),
                getSupportedResponseTypes(activeGrants),
                getSupportedGrantTypes(activeGrants),
                getSubjectTypesSupported(),
                getIdTokenSigningAlgValuesSupported(),
                serverServices.getSupportedScopes().getSupportedScopes().keySet().stream().collect(Collectors.toList()),
                getTokenEndpointAuthMethodsSupported(),
                serverServices.getSupportedClaims().getClaims().stream().collect(Collectors.toList()),
                getCodeChallengeMethodsSupported()
        );
    }

    private List<String> getSupportedGrantTypes(ActiveGrantsConfiguration activeGrants) {
        return Arrays.asList(
                activeGrants.isImplicit() ? "implicit":null,
                activeGrants.isAuthorizationCode() ? "authorization_code":null,
                activeGrants.isRefreshToken() ? "refresh_token":null,
                activeGrants.isResourceOwnerPasswordCredentials() ? "password":null,
                activeGrants.isClientCredentials() ? "client_credentials":null,
                activeGrants.isDeviceAuthorization() ? "urn:ietf:params:oauth:grant-type:device_code":null
        ).stream().filter(e -> e != null).collect(Collectors.toList());
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

    private List<String> getSupportedResponseTypes(ActiveGrantsConfiguration activeGrants) {
        List<String> result = new ArrayList<>();

        result.add("id_token");

        if(activeGrants.isAuthorizationCode())
            result.addAll(Arrays.asList("code", "code id_token"));

        if(activeGrants.isImplicit())
            result.addAll(Arrays.asList("token", "id_token token"));

        if(activeGrants.isAuthorizationCode() && activeGrants.isImplicit())
            result.addAll(Arrays.asList("code id_token token", "code token"));

        return result;
    }

    public String path(String suffix){
        return issuer + suffix;
    }

    @Override
    public void invokeOn(Exchange exc) throws Exception {
        exc.setResponse(new ResponseBuilder().statuscode(200).body(new ObjectMapper().writeValueAsString(wellKnown)).build());
    }
}
