package com.bornium.security.oauth2openid;

import com.bornium.security.oauth2openid.client.OAuth2AuthorizationServerData;
import com.bornium.security.oauth2openid.client.OAuth2ClientData;
import com.predic8.membrane.core.HttpRouter;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.RuleManager;
import com.predic8.membrane.core.config.security.KeyStore;
import com.predic8.membrane.core.config.security.SSLParser;
import com.predic8.membrane.core.config.security.TrustStore;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.resolver.ResolverMap;
import com.predic8.membrane.core.rules.AbstractServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxyKey;
import com.predic8.membrane.core.transport.ssl.SSLContext;
import com.predic8.membrane.core.transport.ssl.StaticSSLContext;

import java.net.URISyntaxException;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class UtilMembrane {

//    public static com.nogiax.http.Exchange convertFromMembraneExchange(Exchange membraneExc)
//    {
//        com.nogiax.http.Exchange result = new com.nogiax.http.Exchange(null,null);
//
//        convertFromMembraneRequest(membraneExc, result);
//        convertFromMembraneResponse(membraneExc, result);
//
//        return result;
//    }

    public static Router startMembraneWithProxies(ServiceProxy... sps) throws Exception {
        HttpRouter router = new HttpRouter();
        router.setHotDeploy(false);

        for (ServiceProxy sp : sps)
            router.getRuleManager().addProxy(sp, RuleManager.RuleDefinitionSource.MANUAL);

        router.start();
        return router;
    }

    private static ServiceProxy createServiceProxy(int spPort, AbstractServiceProxy.Target target, AbstractInterceptor... interceptors) {
        if (target == null)
            target = new AbstractServiceProxy.Target(null, -1);
        if (ConstantsTest.PROTOCOL.equals("https") && target.getSslParser() == null) {
            SSLParser parser = new SSLParser();
            target.setSslParser(parser);
        }

        ServiceProxy sp = new ServiceProxy(new ServiceProxyKey(spPort), target.getHost(), target.getPort());

        if (ConstantsTest.PROTOCOL.equals("https")) {
            SSLParser ssl = new SSLParser();
            ssl.setKeyStore(new KeyStore());
            ssl.getKeyStore().setLocation("classpath:/keystore.jks");
            ssl.getKeyStore().setKeyPassword("secret");
            ssl.getKeyStore().setPassword("secret");
            ssl.setTrustStore(new TrustStore());
            ssl.getTrustStore().setLocation("classpath:/keystore.jks");
            ssl.getTrustStore().setPassword("secret");
            ssl.setEndpointIdentificationAlgorithm("HTTPS");
            sp.setSslInboundParser(ssl);
        }

        target.setSslParser(new SSLParser());

        for (AbstractInterceptor interceptor : interceptors)
            sp.getInterceptors().add(interceptor);

        return sp;
    }

    public static ServiceProxy createAuthorizationServerProxy() {
        return createServiceProxy(ConstantsTest.PORT_AUTHORIZATION_SERVER, null, new AuthorizationServerInterceptor());
    }

    public static ServiceProxy createWebApplicationClientProxy(AbstractServiceProxy.Target protectedResource) {
        return createServiceProxy(ConstantsTest.PORT_CLIENT, protectedResource, new WebApplicationClientInterceptor());
    }

    public static OAuth2ClientData getDefaultCodeGrantClientData() {
        return new OAuth2ClientData(ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, Constants.PARAMETER_VALUE_CODE, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI, ConstantsTest.CLIENT_DEFAULT_SCOPE_OPENID);
    }

    public static OAuth2AuthorizationServerData getDefaultAuthorizationServerData() {
        return new OAuth2AuthorizationServerData(ConstantsTest.SERVER_AUTHORIZATION_ENDPOINT, ConstantsTest.SERVER_TOKEN_ENDPOINT, ConstantsTest.SERVER_USERINFO_ENDPOINT);
    }

    public static Exchange followRedirect(Exchange responseProtectedResource) throws URISyntaxException {
        return new com.predic8.membrane.core.http.Request.Builder().get(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION)).buildExchange();
    }

    public static Client createDefaultClient() {
        return new Client(ConstantsTest.CLIENT_DEFAULT_ID, ConstantsTest.CLIENT_DEFAULT_SECRET, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI);
    }

    public static UserMembrane createDefaultUser() {
        UserMembrane userMembrane = new UserMembrane(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD);
        userMembrane.getClaims().put(Constants.CLAIM_SUB, String.valueOf(0));
        userMembrane.getClaims().put(Constants.CLAIM_WEBSITE, "https://github.com/xorpherion/OAuth2-OpenID");
        userMembrane.getClaims().put(ConstantsTest.CUSTOM_CLAIM_NAME, ConstantsTest.CUSTOM_CLAIM_VALUE);

        return userMembrane;
    }

    public static Client createDefaultClient2() {
        return new Client(ConstantsTest.CLIENT_DEFAULT_ID2, ConstantsTest.CLIENT_DEFAULT_SECRET2, ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI);
    }

    public static SSLContext doNotValidateSSLCertificate() {
        if (ConstantsTest.PROTOCOL.equals("https")) {
            SSLParser parser = new SSLParser();
            parser.setTrustStore(new TrustStore());
            parser.getTrustStore().setLocation("classpath:/keystore.jks");
            parser.getTrustStore().setPassword("secret");
            parser.setKeyStore(new KeyStore());
            parser.getKeyStore().setLocation("classpath:/keystore.jks");
            parser.getKeyStore().setKeyPassword("secret");
            parser.setIgnoreTimestampCheckFailure(true);
            parser.setClientAuth(null);
            SSLContext ctx = new StaticSSLContext(parser, new ResolverMap(), null);
            return ctx;
        }
        return null;
    }
}
