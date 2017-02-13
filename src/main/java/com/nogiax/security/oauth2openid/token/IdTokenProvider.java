package com.nogiax.security.oauth2openid.token;

import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.server.endpoints.Parameters;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

import java.time.Duration;
import java.util.Map;

/**
 * Created by Xorpherion on 29.01.2017.
 */
public class IdTokenProvider {

    private final RsaJsonWebKey rsaJsonWebKey;

    public IdTokenProvider() throws JoseException {
        long time = System.nanoTime();
        rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        time = System.nanoTime() - time;
        System.out.println(time / 1000000000d);
        rsaJsonWebKey.setKeyId("k1");
        rsaJsonWebKey.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        rsaJsonWebKey.setUse("sig");
    }

    public String getJwk() {
        return "{\"keys\": [ " + rsaJsonWebKey.toJson() + "]}";
    }

    public String createIdToken(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, String> claims) throws JoseException {
        JwtClaims jwtClaims = createClaims(issuer, subject, clientidOfRecipient, validFor, authTime, nonce, claims);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        return jws.getCompactSerialization();
    }

    private JwtClaims createClaims(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, String> claims) {
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setIssuer(issuer);
        jwtClaims.setSubject(subject);
        jwtClaims.setAudience(clientidOfRecipient);
        jwtClaims.setIssuedAtToNow();
        NumericDate expiration = NumericDate.now();
        expiration.addSeconds(validFor.getSeconds());
        jwtClaims.setExpirationTime(expiration);
        jwtClaims.setNotBeforeMinutesInThePast(2);

        claims.put(Constants.CLAIM_NONCE, nonce);
        claims.put(Constants.CLAIM_AUTH_TIME, authTime);
        claims.put(Constants.CLAIM_AUTHORIZED_PARTY, clientidOfRecipient);
        claims = Parameters.stripEmptyParams(claims);

        for (String claim : claims.keySet())
            jwtClaims.setClaim(claim, claims.get(claim));
        return jwtClaims;
    }
}
