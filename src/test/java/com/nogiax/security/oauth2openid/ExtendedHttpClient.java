package com.nogiax.security.oauth2openid;

import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.transport.http.HttpClient;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;

/**
 * Created by Xorpherion on 30.01.2017.
 */
public class ExtendedHttpClient {

    HttpClient client;
    HashSet<String> cookies;

    public ExtendedHttpClient(){
        client = new HttpClient();
        cookies = new HashSet<>();
    }


    public Exchange call(Exchange exc) throws Exception {

            exc.getRequest().getHeader().add("Cookie",foldCookies());
        Exchange res = client.call(exc);
        if(res.getResponse().getHeader().getFirstValue("Set-Cookie") != null)
            cookies.add(res.getResponse().getHeader().getFirstValue("Set-Cookie"));
        if(res.getResponse().isRedirect())
            return call(followRedirect(res));
        return res;
    }

    private Exchange followRedirect(Exchange responseProtectedResource) throws URISyntaxException {
        URI uri = new URI(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
        if(uri.isAbsolute()) {
            Exchange res = new com.predic8.membrane.core.http.Request.Builder().get(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION)).buildExchange();
            responseProtectedResource.setOriginalRequestUri(uri.toString());
            res.getDestinations().clear();
            res.getDestinations().add(responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
            return res;
        }
        else{
            uri = new URI("http://" + responseProtectedResource.getRequest().getHeader().getHost() + responseProtectedResource.getResponse().getHeader().getFirstValue(Constants.HEADER_LOCATION));
            Exchange res = new com.predic8.membrane.core.http.Request.Builder().get(uri.toString()).buildExchange();
            responseProtectedResource.setOriginalRequestUri(uri.toString());
            res.getDestinations().clear();
            res.getDestinations().add(uri.toString());
            return res;
        }

    }

    private String foldCookies(){
        StringBuilder builder = new StringBuilder();
        for(String cookie : cookies){
            builder.append(cookie).append(",");
        }
        if(cookies.size() > 0)
            builder.deleteCharAt(builder.length()-1);
        return builder.toString();
    }

}
