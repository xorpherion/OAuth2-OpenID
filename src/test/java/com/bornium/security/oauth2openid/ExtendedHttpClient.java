package com.bornium.security.oauth2openid;

import com.bornium.security.oauth2openid.unit.Common;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.transport.http.HttpClient;
import com.predic8.membrane.core.transport.ssl.SSLContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by Xorpherion on 30.01.2017.
 */
public class ExtendedHttpClient {

    HttpClient client;
    HashSet<String> cookies;
    SSLContext ctx;

    public ExtendedHttpClient() throws KeyManagementException, NoSuchAlgorithmException {
        ctx = UtilMembrane.doNotValidateSSLCertificate();
        client = new HttpClient();
        cookies = new HashSet<>();
    }


    public Exchange call(Exchange exc) throws Exception {

        exc.getRequest().getHeader().add("Cookie", foldCookies());
        exc.setProperty(Exchange.SSL_CONTEXT, ctx);
        Exchange res = client.call(exc);
        String locationHeader = exc.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION);
        if(locationHeader != null && locationHeader.contains("params=")) {
            Map<String, String> loginParams = Common.convertLoginPageParamsToMap(locationHeader);
            if (!loginParams.isEmpty())
                res.setProperty(Constants.GRANT_CONTEXT_ID, loginParams.get(Constants.GRANT_CONTEXT_ID));
        }
        if (res.getResponse().getHeader().getFirstValue("Set-Cookie") != null)
            cookies.add(res.getResponse().getHeader().getFirstValue("Set-Cookie"));
        if (res.getResponse().isRedirect())
            return call(followRedirect(res));
        return res;
    }

    private Exchange followRedirect(Exchange responseProtectedResource) throws URISyntaxException {
        URI uri = new URI(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
        if (uri.isAbsolute()) {
            Exchange res = new com.predic8.membrane.core.http.Request.Builder().get(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION)).buildExchange();
            responseProtectedResource.setOriginalRequestUri(uri.toString());
            res.getDestinations().clear();
            res.getDestinations().add(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
            return res;
        } else {
            uri = new URI(ConstantsTest.PROTOCOL + "://" + responseProtectedResource.getRequest().getHeader().getHost() + responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
            Exchange res = new com.predic8.membrane.core.http.Request.Builder().get(uri.toString()).buildExchange();
            responseProtectedResource.setOriginalRequestUri(uri.toString());
            res.getDestinations().clear();
            res.getDestinations().add(uri.toString());
            return res;
        }

    }

    private String foldCookies() {
        StringBuilder builder = new StringBuilder();
        for (String cookie : cookies) {
            builder.append(cookie).append(",");
        }
        if (cookies.size() > 0)
            builder.deleteCharAt(builder.length() - 1);
        return builder.toString();
    }

}
