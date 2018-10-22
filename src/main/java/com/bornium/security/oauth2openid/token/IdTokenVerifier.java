package com.bornium.security.oauth2openid.token;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Xorpherion on 08.02.2017.
 */
public class IdTokenVerifier {
    private JwksVerificationKeyResolver jwksResolver;

    public IdTokenVerifier(String jwks) throws JoseException {
        jwksResolver = new JwksVerificationKeyResolver(new JsonWebKeySet(jwks).getJsonWebKeys());
    }

    public Map<String,Object> verifySignedJwt(String jwt) throws InvalidJwtException {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(jwksResolver)
                .build();

        JwtClaims claims = consumer.processToClaims(jwt);

        HashMap<String, Object> result = new HashMap<>();
        for (String claim : claims.getClaimNames())
            result.put(claim, claims.getClaimValue(claim));

        return result;
    }

    public Map<String, Object> verifyAndGetClaims(String idToken) throws InvalidJwtException {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setSkipDefaultAudienceValidation()
                .setVerificationKeyResolver(jwksResolver)
                .build();

        JwtClaims claims = consumer.processToClaims(idToken);

        HashMap<String, Object> result = new HashMap<>();
        for (String claim : claims.getClaimNames())
            result.put(claim, claims.getClaimValue(claim));

        return result;
    }

    public Map<String, String> verifyAndGetClaims(String idToken, String issuer) throws InvalidJwtException {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(issuer)
                .setSkipDefaultAudienceValidation()
                .setVerificationKeyResolver(jwksResolver)
                .build();

        JwtClaims claims = consumer.processToClaims(idToken);

        HashMap<String, String> result = new HashMap<>();
        for (String claim : claims.getClaimNames())
            result.put(claim, String.valueOf(claims.getClaimValue(claim)));

        return result;
    }

    public Map<String, String> verifyAndGetClaims(String idToken, String issuer, String clientId) throws InvalidJwtException {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(issuer)
                .setExpectedAudience(clientId)
                .setVerificationKeyResolver(jwksResolver)
                .build();

        JwtClaims claims = consumer.processToClaims(idToken);

        HashMap<String, String> result = new HashMap<>();
        for (String claim : claims.getClaimNames())
            result.put(claim, String.valueOf(claims.getClaimValue(claim)));

        return result;
    }
}
