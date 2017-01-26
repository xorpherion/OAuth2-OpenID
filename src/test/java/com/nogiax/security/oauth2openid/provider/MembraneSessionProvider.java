package com.nogiax.security.oauth2openid.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nogiax.http.Exchange;
import com.nogiax.security.oauth2openid.Session;
import com.nogiax.security.oauth2openid.Util;
import com.nogiax.security.oauth2openid.providers.SessionProvider;
import com.predic8.membrane.core.interceptor.authentication.session.SessionManager;
import com.predic8.membrane.core.rules.NullRule;

/**
 * Created by Xorpherion on 26.01.2017.
 */
public class MembraneSessionProvider implements SessionProvider {

    String excPropertyName = "membrane_session";
    String excSessionIdPropertyName = "SESSION_ID";
    String sessionKeyPrefix = "oauth2_session";

    SessionManager sessionManager;

    public MembraneSessionProvider(String sessionName){
        sessionManager = new SessionManager();
        sessionManager.setCookieName(sessionName);
    }

    @Override
    public Session getSession(Exchange exc) {
        com.predic8.membrane.core.exchange.Exchange memExc = new com.predic8.membrane.core.exchange.Exchange(null);
        memExc.setRequest(Util.convertToMembraneRequest(exc.getRequest()));
        memExc.setRule(new NullRule());

        SessionManager.Session memSession = sessionManager.getOrCreateSession(memExc);

        exc.getProperties().put(excPropertyName,memExc.getProperty(excSessionIdPropertyName));

        return new Session() {

            SessionManager.Session session = memSession;
            @Override
            public String getValue(String key) {
                return session.getUserAttributes().get(prefixKey(key));
            }

            @Override
            public void putValue(String key, String value) throws JsonProcessingException {
                session.getUserAttributes().put(prefixKey(key),value);
            }

            private String prefixKey(String key){
                return sessionKeyPrefix + "_" + key;
            }
        } ;
    }

    public void postProcessSession(Exchange exc, com.predic8.membrane.core.exchange.Exchange memExc){
        Object sessionId = exc.getProperties().get(excSessionIdPropertyName);

        if(sessionId != null && exc.getResponse() != null){
            memExc.setProperty(excSessionIdPropertyName,sessionId);
            sessionManager.postProcess(memExc);
        }


    }
}
