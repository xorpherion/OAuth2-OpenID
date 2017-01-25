package com.nogiax.security.oauth2openid.integration;

import com.nogiax.http.Exchange;
import com.predic8.membrane.core.HttpRouter;
import com.predic8.membrane.core.rules.ServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxyKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class OAuth2 {

    @Test
    void pseudoMain() throws Exception {

        System.out.println("starting");
        HttpRouter router = new HttpRouter();
        router.setHotDeploy(false);
        int listenPort = 4000;

        String protectedTargetHost = "www.google.de";
        int protectedTargetPort = 80;

        ServiceProxyKey authorizationServerKey = new ServiceProxyKey(listenPort);

        ServiceProxy authorizationServerProxy = new ServiceProxy(authorizationServerKey,protectedTargetHost,protectedTargetPort);
        router.add(authorizationServerProxy);

        router.start();

        System.out.println("running");
        Thread.sleep(1000);
        router.stop();
        System.out.println("done");
    }
}
