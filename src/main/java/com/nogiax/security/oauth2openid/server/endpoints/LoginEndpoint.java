package com.nogiax.security.oauth2openid.server.endpoints;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nogiax.http.Exchange;
import com.nogiax.http.Response;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.http.util.BodyUtil;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;
import com.nogiax.security.oauth2openid.Session;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class LoginEndpoint extends Endpoint {

    public LoginEndpoint(ServerProvider serverProvider) {
        super(serverProvider, Constants.ENDPOINT_LOGIN, Constants.ENDPOINT_CONSENT);
    }

    @Override
    public boolean checkParametersOAuth2(Exchange exc) throws Exception {
        return true;
    }

    @Override
    public boolean invokeOnOAuth2(Exchange exc) throws Exception {
        log.info("Login endpoint");
        if(exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_LOGIN)) {
            if (hasSentLoginData(exc)){
                Map<String,String> params = BodyUtil.bodyToParams(exc.getRequest().getBody());
                if(!params.containsKey(Constants.LOGIN_USERNAME) && !params.containsKey(Constants.LOGIN_PASSWORD)) {
                    exc.setResponse(sendLoginpage());
                    return true;
                }
                String username = params.get(Constants.LOGIN_USERNAME);
                String password = params.get(Constants.LOGIN_PASSWORD);
                if(!serverProvider.getUserDataProvider().verifyUser(username,password)){
                    exc.setResponse(sendLoginpage());
                    return true;
                }
                Session session = serverProvider.getSessionProvider().getSession(exc);
                session.putValue(Constants.SESSION_LOGGED_IN,Constants.VALUE_YES);
                exc.setResponse(redirectToConsent());
                return true;
            }
            else
                exc.setResponse(sendLoginpage());
        }
        else if(exc.getRequest().getUri().getPath().endsWith(Constants.ENDPOINT_CONSENT)) {
            log.info("consent page");
            if(hasSentConsent(exc)){

            }else
                exc.setResponse(sendConsentpage());
        }

        return true;
    }



    private Response sendLoginpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadLoginpage()).build();
    }
    private Response sendConsentpage() throws IOException {
        return new ResponseBuilder().statuscode(200).body(loadConsentpage()).build();
    }


    @Override
    public boolean checkParametersOpenID(Exchange exc) throws Exception {
        return true;
    }

    @Override
    public boolean invokeOnOpenId(Exchange exc) throws Exception {
        return true;
    }

    @Override
    public String getScope(Exchange exc) throws Exception {
        return null;
    }

    private boolean hasSentLoginData(Exchange exc){
        if(exc.getRequest().getBody().contains(Constants.LOGIN_USERNAME) && exc.getRequest().getBody().contains(Constants.LOGIN_PASSWORD))
            return true;
        return false;
    }

    private boolean hasSentConsent(Exchange exc){
        return false;
    }

    private String loadLoginpage() throws IOException {
        return loadPage("login.html");
    }

    private String loadConsentpage() throws IOException {
        return loadPage("consent.html");
    }

    private String loadPage(String page) throws IOException {
        return CharStreams.toString(new InputStreamReader(this.getClass().getResourceAsStream("/static/logindialog/" + page), Charsets.UTF_8));
    }
}
