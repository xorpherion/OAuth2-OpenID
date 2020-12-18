package com.bornium.security.oauth2openid.integration;

import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.ConstantsTest;
import com.bornium.security.oauth2openid.ExtendedHttpClient;
import com.bornium.security.oauth2openid.UtilMembrane;
import com.bornium.security.oauth2openid.unit.Common;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.http.Request;
import com.predic8.membrane.core.rules.AbstractServiceProxy;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class OAuth2 {

    Logger log = LoggerFactory.getLogger(OAuth2.class);
    Lock l = new ReentrantLock();

    /*@Disabled
    @Test
    void pseudoMain() throws Exception {
        Router r = HttpRouter.init(getClass().getResource("/proxies.xml").toString());
        boolean running = true;
        while (running)
            Thread.sleep(1000);
    }*/

    @Disabled
    @Test
    void testStartAuthServerAndClient() throws Exception {
        Router authorizationServer = UtilMembrane.startMembraneWithProxies(UtilMembrane.createAuthorizationServerProxy());
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target(ConstantsTest.HOST_AUTHORIZATION_SERVER.replace(ConstantsTest.PROTOCOL+"://", ""), ConstantsTest.PORT_AUTHORIZATION_SERVER)));
        boolean running = true;
        while (running)
            Thread.sleep(1000);
        webApplicationClient.stop();
        authorizationServer.stop();
    }

    @Test
    void testSuccessfulAuthorizationFlow() throws Exception {
        Router authorizationServer = UtilMembrane.startMembraneWithProxies(UtilMembrane.createAuthorizationServerProxy());
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target(ConstantsTest.HOST_AUTHORIZATION_SERVER.replace(ConstantsTest.PROTOCOL+"://", ""), ConstantsTest.PORT_AUTHORIZATION_SERVER)));

        ExtendedHttpClient client = new ExtendedHttpClient();

        Exchange requestDirectCallToProtectedResource = new Request.Builder().get(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_USERINFO).buildExchange();
        Exchange responseDirectCallToProtectedResource = client.call(requestDirectCallToProtectedResource);

        assertAll("Direct access of resource server",
                () -> assertEquals(401, responseDirectCallToProtectedResource.getResponse().getStatusCode(), "Statuscode was not OK"));

        Exchange requestProtectedResource = new Request.Builder().get(ConstantsTest.URL_PROTECTED_RESOURCE).buildExchange();
        Exchange responseProtectedResource = client.call(requestProtectedResource);

        assertAll("Login page",
                () -> assertEquals(200, responseProtectedResource.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        Map<String, String> paramsAsMap = Common.convertLoginPageParamsToMap(responseProtectedResource.getDestinations().get(0));

        Exchange requestLogin = new Request.Builder().post(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_LOGIN).body("username=" + ConstantsTest.USER_DEFAULT_NAME + "&password=" + ConstantsTest.USER_DEFAULT_PASSWORD + "&login_state=" + paramsAsMap.get("state") + "&" + Constants.GRANT_CONTEXT_ID + "=" + paramsAsMap.get(Constants.GRANT_CONTEXT_ID)).buildExchange();
        Exchange responseLogin = client.call(requestLogin);

        assertAll("Consent page",
                () -> assertEquals(200, responseLogin.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        paramsAsMap = Common.convertLoginPageParamsToMap(responseLogin.getDestinations().get(0));

        Exchange requestConsent = new Request.Builder().post(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_CONSENT).body("consent=yes&login_state=" + paramsAsMap.get("state") + "&" + Constants.GRANT_CONTEXT_ID + "=" + paramsAsMap.get(Constants.GRANT_CONTEXT_ID)).buildExchange();
        Exchange responseConsent = client.call(requestConsent);

        assertAll("Protected resource",
                () -> assertEquals(200, responseConsent.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        log.info(responseConsent.getResponse().getBodyAsStringDecoded());

        authorizationServer.stop();
        webApplicationClient.stop();
    }

}
