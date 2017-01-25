package com.nogiax.security.oauth2openid.integration;

import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.Util;
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

        ServiceProxy authorizationServerProxy = new ServiceProxy(authorizationServerKey,protectedTargetHost,protectedTargetPort);
        router.add(authorizationServerProxy);

        router.start();

        log.info("running");

        router.stop();
        log.info("done");
    }

    @Test
    void pseudoMain2() throws Exception{
        pseudoMain();
    }

    @Test
    void testSuccessfulAuthorizationFlow() throws Exception{
        Router authorizationServer = Util.startMembraneWithProxies(Util.createAuthorizationServerProxy());
        Router webApplicationClient = Util.startMembraneWithProxies(Util.createWebApplicationClientProxy(new AbstractServiceProxy.Target("www.google.de",80)));

        HttpClient httpClient = new HttpClient();

        Exchange requestProtectedResource = new Request.Builder().get(Constants.URL_CLIENT).buildExchange();

        Exchange responseProtectedResource = httpClient.call(requestProtectedResource);

    }
}
