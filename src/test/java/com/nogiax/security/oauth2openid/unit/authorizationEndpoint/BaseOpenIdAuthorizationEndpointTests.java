package com.nogiax.security.oauth2openid.unit.authorizationEndpoint;

import com.nogiax.http.Exchange;
import com.nogiax.http.Method;
import com.nogiax.security.oauth2openid.Constants;
import com.nogiax.security.oauth2openid.ConstantsTest;
import com.nogiax.security.oauth2openid.unit.Common;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Created by Xorpherion on 09.02.2017.
 */
public abstract class BaseOpenIdAuthorizationEndpointTests extends BaseAuthorizationEndpointTests {

    public abstract String getResponseMode();
    public abstract String getNonce();
    public abstract String getPrompt();
    public abstract String getMaxAge();
    public abstract String getIdTokenHint();
    public abstract String getLoginHint();
    public String getAuthenticationContextClass(){
        return "43078u29ß41238930574z3432ß89437ß4ur80j9uiege";
    }
    public abstract String getClaims();

    @Override
    public String getClientId() {
        return ConstantsTest.CLIENT_DEFAULT_ID;
    }

    @Override
    public String getRedirectUri() {
        return ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI;
    }

    @Override
    public String getState() {
        return ConstantsTest.CLIENT_DEFAULT_STATE;
    }

    @Test
    @Override
    public Exchange goodPreLoginRequest() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(),getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange goodPreLoginRequestPost() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        return Common.createOpenIdAuthRequest(Method.POST,getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(),getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange responseModeQuery() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),Constants.PARAMETER_VALUE_QUERY,getNonce(),getPrompt(),getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc = server.invokeOn(exc);
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        return Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                            () -> assertEquals(false, Common.getParamsFromRedirectResponse(exc,false).isEmpty())
                    );
                });
    }

    @Test
    public Exchange responseModeFragment() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),Constants.PARAMETER_VALUE_FRAGMENT,getNonce(),getPrompt(),getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc = server.invokeOn(exc);
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        return Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                            () -> assertEquals(false, Common.getParamsFromRedirectResponse(exc,true).isEmpty())
                    );
                });
    }

    @Test
    public Exchange responseTypeNone() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(Constants.PARAMETER_VALUE_NONE,getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(),getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc = server.invokeOn(exc);
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        return Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode()),
                            () -> assertEquals(new URI(ConstantsTest.CLIENT_DEFAULT_REDIRECT_URI).getPath(), Common.getResponseLocationHeaderAsUri(exc).getPath()),
                            () -> assertEquals(1, Common.getParamsFromRedirectResponse(exc,false).size())
                    );
                });
    }

    @Test
    public Exchange promptLoginForcesNewLogin() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodPostLoginRequest();
                        String cookie = Common.extractSessionCookie(exc);
                        exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),Constants.PARAMETER_VALUE_LOGIN,getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc.getRequest().getHeader().append(Constants.HEADER_COOKIE,cookie);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange promptNoneResultsInError() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),Constants.PARAMETER_VALUE_NONE,getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_CLIENT_CALLBACK, Common.getResponseLocationHeaderAsUri(exc).getPath()),
                            () -> assertEquals(Constants.ERROR_INTERACTION_REQUIRED, Common.getParamsFromRedirectResponse(exc,isImplicit()).get(Constants.PARAMETER_ERROR))
                    );
                });
    }

    @Test
    public Exchange promptNoneWhenLoggedIn() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = goodPostLoginRequest();
                        String cookie = Common.extractSessionCookie(exc);
                        exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),Constants.PARAMETER_VALUE_NONE,getMaxAge(),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc.getRequest().getHeader().append(Constants.HEADER_COOKIE,cookie);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_CLIENT_CALLBACK, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange elapsedMaxAgeForcesLogin() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(), String.valueOf(0),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc = server.invokeOn(exc);
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        exc = Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                        String cookie = Common.extractSessionCookie(exc);
                        exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(), String.valueOf(0),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc.getRequest().getHeader().append(Constants.HEADER_COOKIE,cookie);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_LOGIN, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }

    @Test
    public Exchange notElapsedMaxAgeIsOk() throws Exception {
        return Common.testExchangeOn(server,
                () -> {
                    try {
                        Exchange exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(), String.valueOf(100),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc = server.invokeOn(exc);
                        Map<String, String> loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createLoginRequest(ConstantsTest.USER_DEFAULT_NAME, ConstantsTest.USER_DEFAULT_PASSWORD, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        loginParams = Common.convertLoginPageParamsToMap(exc.getResponse().getHeader().getValue(Constants.HEADER_LOCATION));
                        exc = Common.createConsentRequest(Constants.VALUE_YES, loginParams.get(Constants.PARAMETER_STATE), Common.extractSessionCookie(exc));
                        exc = server.invokeOn(exc);
                        exc = Common.createPostLoginRequest(Common.extractSessionCookie(exc));
                        String cookie = Common.extractSessionCookie(exc);
                        exc = Common.createOpenIdAuthRequest(getResponseType(),getClientId(),getRedirectUri(),getScope(),getState(),getResponseMode(),getNonce(),getPrompt(), String.valueOf(0),getIdTokenHint(),getLoginHint(),getAuthenticationContextClass(),getClaims());
                        exc.getRequest().getHeader().append(Constants.HEADER_COOKIE,cookie);
                        return exc;
                    } catch (Exception e) {
                        return Common.defaultExceptionHandling(e);
                    }
                },
                (exc) -> {
                    assertAll(
                            Common.getMethodName(),
                            () -> assertEquals(303, exc.getResponse().getStatuscode(), "Statuscode was not 303"),
                            () -> assertEquals(Constants.ENDPOINT_CLIENT_CALLBACK, Common.getResponseLocationHeaderAsUri(exc).getPath())
                    );
                });
    }
}
