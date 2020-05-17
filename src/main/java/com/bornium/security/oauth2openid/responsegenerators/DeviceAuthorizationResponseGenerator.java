package com.bornium.security.oauth2openid.responsegenerators;

import com.bornium.http.Exchange;
import com.bornium.http.util.UriUtil;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.server.ServerServices;
import com.bornium.security.oauth2openid.token.Token;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class DeviceAuthorizationResponseGenerator extends ResponseGenerator {
    private final String issuer;

    public DeviceAuthorizationResponseGenerator(ServerServices serverServices, Exchange exc) {
        super(serverServices, exc);
        issuer = serverServices.getProvidedServices().getIssuer();
    }

    @Override
    public Map<String, String> invokeResponse() throws Exception {
        String clientId = getSession().getValue(Constants.PARAMETER_CLIENT_ID);
        String scope = getSession().getValue(Constants.PARAMETER_SCOPE);

        Map result = new HashMap();

        Token deviceToken = getTokenManager().addTokenToManager(getTokenManager().getDeviceCodes(), getTokenManager().createDeviceTokenWithDefaultDuration(clientId, scope));

        String deviceCode = deviceToken.getValue().replaceFirst("^pre:", "");
        String userCode = deviceToken.getUsername();

        getTokenManager().addTokenToManager(getTokenManager().getUserCodes(), getTokenManager().createUserToken(userCode, deviceCode, scope));

        result.put(Constants.PARAMETER_DEVICE_CODE, deviceCode);
        result.put(Constants.PARAMETER_USER_CODE, userCode);
        result.put(Constants.PARAMETER_VERIFICATION_URI, issuer + Constants.ENDPOINT_VERIFICATION);
        result.put(Constants.PARAMETER_VERIFICATION_URI_COMPLETE, issuer + Constants.ENDPOINT_VERIFICATION + "?" + Constants.PARAMETER_USER_CODE + "=" + UriUtil.encode(userCode));
        result.put(Constants.PARAMETER_EXPIRES_IN, deviceToken.getValidFor().get(ChronoUnit.SECONDS));
        result.put(Constants.PARAMETER_INTERVAL, 5);

        return result;
    }
}
