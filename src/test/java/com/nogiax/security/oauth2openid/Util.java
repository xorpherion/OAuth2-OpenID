package com.nogiax.security.oauth2openid;

import com.nogiax.http.Method;
import com.nogiax.http.Request;
import com.nogiax.http.Response;
import com.predic8.membrane.core.HttpRouter;
import com.predic8.membrane.core.Router;
import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.http.HeaderField;
import com.predic8.membrane.core.interceptor.AbstractInterceptor;
import com.predic8.membrane.core.rules.AbstractServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxy;
import com.predic8.membrane.core.rules.ServiceProxyKey;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;

/**
 * Created by Xorpherion on 25.01.2017.
 */
public class Util {

//    public static com.nogiax.http.Exchange convertFromMembraneExchange(Exchange membraneExc)
//    {
//        com.nogiax.http.Exchange result = new com.nogiax.http.Exchange(null,null);
//
//        convertFromMembraneRequest(membraneExc, result);
//        convertFromMembraneResponse(membraneExc, result);
//
//        return result;
//    }

    public static Response convertFromMembraneResponse(com.predic8.membrane.core.http.Response membraneResponse) {
        if(membraneResponse != null){
            Response result = new Response();
            result.setStatuscode(membraneResponse.getStatusCode());
            result.setBody(membraneResponse.getBodyAsStringDecoded());
            for(HeaderField header : membraneResponse.getHeader().getAllHeaderFields())
                result.getHeader().append(header.getHeaderName().toString(),header.getValue());
            return result;
        }
        return null;
    }

    public static Request convertFromMembraneRequest(com.predic8.membrane.core.http.Request membraneRequest) {
        if(membraneRequest != null){
            Request result = new Request();
            result.setUri(URI.create(membraneRequest.getUri()));
            result.setMethod(Method.fromString(membraneRequest.getMethod()));
            result.setBody(membraneRequest.getBodyAsStringDecoded());
            for(HeaderField header : membraneRequest.getHeader().getAllHeaderFields())
                result.getHeader().append(header.getHeaderName().toString(),header.getValue());
            return result;
        }
        return null;
    }

    public static com.predic8.membrane.core.http.Request convertToMembraneRequest(Request request){
        if(request != null){
            com.predic8.membrane.core.http.Request result = new com.predic8.membrane.core.http.Request();
            result.setUri(request.getUri().toString());
            result.setMethod(request.getMethod().toString());
            result.setBodyContent(request.getBody().getBytes(Charset.defaultCharset()));
            for(String headername : request.getHeader().getHeaderNames())
                result.getHeader().add(headername,request.getHeader().getValue(headername));
            return result;
        }
        return null;
    }

    public static com.predic8.membrane.core.http.Response convertToMembraneResponse(Response response){
        if(response != null){
            com.predic8.membrane.core.http.Response result = new com.predic8.membrane.core.http.Response();
            result.setStatusCode(response.getStatuscode());
            result.setBodyContent(response.getBody().getBytes(Charset.defaultCharset()));
            for(String headername : response.getHeader().getHeaderNames())
                result.getHeader().add(headername,response.getHeader().getValue(headername));
            return result;
        }
        return null;
    }

    public static Router startMembraneWithProxies(ServiceProxy... sps) throws Exception {
        HttpRouter router = new HttpRouter();
        router.setHotDeploy(false);

        for(ServiceProxy sp : sps)
            router.add(sp);

        router.start();
        return router;
    }

    private static ServiceProxy createServiceProxy(int spPort, AbstractServiceProxy.Target target, AbstractInterceptor... interceptors){
        if(target == null)
            target = new AbstractServiceProxy.Target(null,-1);

        ServiceProxy sp = new ServiceProxy(new ServiceProxyKey(spPort),target.getHost(),target.getPort());

        for(AbstractInterceptor interceptor : interceptors)
            sp.getInterceptors().add(interceptor);

        return sp;
    }

    public static ServiceProxy createAuthorizationServerProxy(){
        return createServiceProxy(Constants.PORT_AUTHORIZATION_SERVER, null, new AuthorizationServerInterceptor());
    }

    public static ServiceProxy createWebApplicationClientProxy(AbstractServiceProxy.Target protectedResource) {
        return createServiceProxy(Constants.PORT_CLIENT,protectedResource,new WebApplicationClientInterceptor());
    }
}
