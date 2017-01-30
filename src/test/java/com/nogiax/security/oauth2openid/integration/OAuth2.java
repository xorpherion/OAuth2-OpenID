package com.nogiax.security.oauth2openid.integration;

import com.nogiax.security.oauth2openid.ConstantsTest;
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
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target("www.google.de", 80)));
        boolean running = true;
        while (running)
            Thread.sleep(1000);
        webApplicationClient.stop();
        authorizationServer.stop();
    }

    @Test
    void testSuccessfulAuthorizationFlow() throws Exception {
        Router authorizationServer = UtilMembrane.startMembraneWithProxies(UtilMembrane.createAuthorizationServerProxy());
        Router webApplicationClient = UtilMembrane.startMembraneWithProxies(UtilMembrane.createWebApplicationClientProxy(new AbstractServiceProxy.Target("www.google.de", 80)));

        HttpClient httpClient = new HttpClient();

        Exchange requestProtectedResource = new Request.Builder().get(ConstantsTest.URL_CLIENT).buildExchange();

        Exchange responseProtectedResource = httpClient.call(requestProtectedResource);

        assertAll("Redirect to authorization server",
                () -> assertEquals(307, responseProtectedResource.getResponse().getStatusCode(), "Statuscode was not redirect")
        );

        Exchange requestFollowRedirectToAuthorizationServer = UtilMembrane.followRedirect(responseProtectedResource);

        Exchange responseFollowRedirectToAuthorzationServer = httpClient.call(requestFollowRedirectToAuthorizationServer);

        assertAll("Redirect to login page",
                () -> assertEquals(307, responseFollowRedirectToAuthorzationServer.getResponse().getStatusCode(), "Statuscode was not redirect")
        );

        Exchange requestLoginPage = UtilMembrane.followRedirect(responseFollowRedirectToAuthorzationServer);
    }
}
