package com.nogiax.security.oauth2openid.server.endpoints;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nogiax.http.Exchange;
import com.nogiax.http.ResponseBuilder;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ServerProvider;

import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class LoginEndpoint extends Endpoint {

    public LoginEndpoint(ServerProvider serverProvider) {
        super(serverProvider, Constants.ENDPOINT_LOGIN);
    }

    @Override
    public boolean checkParametersOAuth2(Exchange exc) throws Exception {
        return true;
    }

    @Override
    public boolean invokeOnOAuth2(Exchange exc) throws Exception {
        System.out.println(exc.getRequest().getBody());
        log.info("Login endpoint");
        exc.setResponse(new ResponseBuilder().statuscode(200).body(loadLoginpage()).build());

        return true;
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
