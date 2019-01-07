package com.bornium.security.oauth2openid.token;

import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.server.endpoints.Parameters;
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
        this(generateKey());
    }

    private static RsaJsonWebKey generateKey() throws JoseException {
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        rsaJsonWebKey.setKeyId("k1");
        rsaJsonWebKey.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        rsaJsonWebKey.setUse("sig");
        return rsaJsonWebKey;
    }

    public IdTokenProvider(RsaJsonWebKey rsaJsonWebKey) throws JoseException {
        this.rsaJsonWebKey = rsaJsonWebKey;
    }

    public String getJwk() {
        return "{\"keys\": [ " + rsaJsonWebKey.toJson() + "]}";
    }

    public String createIdToken(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, Object> claims) throws JoseException {
        return createIdToken(createClaims(issuer, subject, clientidOfRecipient, validFor, authTime, nonce, claims));
    }

    public String createIdTokenNoNullClaims(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, Object> claims) throws JoseException {
        return createIdToken(createClaimsNoNulls(issuer,subject,clientidOfRecipient,validFor,authTime,nonce,claims));
    }

    public String createIdToken(JwtClaims claims) throws JoseException {
        return signJwt(claims)
                .getCompactSerialization();
    }

    public JwtClaims createJwtClaims(Duration validFor, Map<String,Object> claims){
        JwtClaims jwtClaims = new JwtClaims();

        NumericDate expiration = NumericDate.now();
        expiration.addSeconds(validFor.getSeconds());
        jwtClaims.setExpirationTime(expiration);

        for (String claim : claims.keySet())
            jwtClaims.setClaim(claim, claims.get(claim));

        return jwtClaims;
    }

    public JsonWebSignature signJwt(JwtClaims claims){
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        return jws;
    }

    public String toString(JsonWebSignature jws) throws JoseException {
        return jws.getCompactSerialization();
    }

    public String createSignedJwt(Duration validFor, Map<String,Object> claims) throws JoseException {
        return toString(signJwt(createJwtClaims(validFor,claims)));
    }

    private JwtClaims createClaims(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, Object> claims) {
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
        claims = Parameters.stripNullParams(claims);

        for (String claim : claims.keySet())
            jwtClaims.setClaim(claim, claims.get(claim));

        return jwtClaims;
    }

    private JwtClaims createClaimsNoNulls(String issuer, String subject, String clientidOfRecipient, Duration validFor, String authTime, String nonce, Map<String, Object> claims) {
        JwtClaims jwtClaims = createClaims(issuer,subject,clientidOfRecipient,validFor,authTime,nonce,claims);

        jwtClaims.getClaimNames().stream().forEach(cln -> {
            if(jwtClaims.getClaimValue(cln) == null)
                jwtClaims.unsetClaim(cln);
        });
        return jwtClaims;
    }

    public RsaJsonWebKey getRsaJsonWebKey() {
        return rsaJsonWebKey;
    }
}
