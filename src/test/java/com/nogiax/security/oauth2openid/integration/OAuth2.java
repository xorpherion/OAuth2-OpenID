package com.nogiax.security.oauth2openid.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nogiax.http.util.UriUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.ExtendedHttpClient;
import com.nogiax.security.oauth2openid.UtilMembrane;
import com.predic8.membrane.core.HttpRouter;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.http.Request;
import com.predic8.membrane.core.rules.AbstractServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxyKey;
import com.predic8.membrane.core.transport.http.HttpClient;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Base64;

import java.net.URI;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class OAuth2 {

    Logger log = LoggerFactory.getLogger(OAuth2.class);

    @Test
    void pseudoMain() throws Exception {

        log.info("starting");
        HttpRouter router = new HttpRouter();
        router.setHotDeploy(false);
        int listenPort = 4000;

        String protectedTargetHost = "www.google.de";
        int protectedTargetPort = 80;

        ServiceProxyKey authorizationServerKey = new ServiceProxyKey(listenPort);

        ServiceProxy authorizationServerProxy = new ServiceProxy(authorizationServerKey, protectedTargetHost, protectedTargetPort);
        router.add(authorizationServerProxy);

        router.start();

        log.info("running");

        router.stop();
        log.info("done");
    }

    @Test
    void testStartAuthServerAndClient() throws Exception {
        Router authorizationServer = UtilMembrane.startMembraneWithProxies(UtilMembrane.createAuthorizationServerProxy());
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target(ConstantsTest.HOST_AUTHORIZATION_SERVER.replace("http://",""), ConstantsTest.PORT_AUTHORIZATION_SERVER)));
        boolean running = true;
        while (running)
            Thread.sleep(1000);
        webApplicationClient.stop();
        authorizationServer.stop();
    }

    @Test
    void testSuccessfulAuthorizationFlow() throws Exception {
        Router authorizationServer = UtilMembrane.startMembraneWithProxies(UtilMembrane.createAuthorizationServerProxy());
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target(ConstantsTest.HOST_AUTHORIZATION_SERVER.replace("http://",""), ConstantsTest.PORT_AUTHORIZATION_SERVER)));

        ExtendedHttpClient client = new ExtendedHttpClient();

        Exchange requestProtectedResource = new Request.Builder().get(ConstantsTest.URL_PROTECTED_RESOURCE).buildExchange();
        Exchange responseProtectedResource = client.call(requestProtectedResource);

        assertAll("Login page",
                () -> assertEquals(200, responseProtectedResource.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        URI uri = new URI(responseProtectedResource.getDestinations().get(0));
        String params = new String(Base64.getDecoder().decode(uri.getFragment().split(Pattern.quote("="))[1]));
        Map<String,String> paramsAsMap = new ObjectMapper().readValue(params,Map.class);

        Exchange requestLogin = new Request.Builder().post(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_LOGIN).body("username="+ ConstantsTest.USER_DEFAULT_NAME+"&password=" + ConstantsTest.USER_DEFAULT_PASSWORD + "&login_state=" + paramsAsMap.get("state")).buildExchange();
        Exchange responseLogin = client.call(requestLogin);

        assertAll("Consent page",
                () -> assertEquals(200, responseLogin.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        uri = new URI(responseLogin.getDestinations().get(0));
        params = new String(Base64.getDecoder().decode(uri.getFragment().split(Pattern.quote("="))[1]));
        paramsAsMap = new ObjectMapper().readValue(params,Map.class);

        Exchange requestConsent = new Request.Builder().post(ConstantsTest.URL_AUTHORIZATION_SERVER + Constants.ENDPOINT_CONSENT).body("consent=yes&login_state=" + paramsAsMap.get("state")).buildExchange();
        Exchange responseConsent = client.call(requestConsent);

        assertAll("Protected resource",
                () -> assertEquals(200, responseConsent.getResponse().getStatusCode(), "Statuscode was not OK")
        );

        log.info(responseConsent.getResponse().getBodyAsStringDecoded());
    }
}
