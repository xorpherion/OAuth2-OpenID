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

    String excSessionPropertyName = "membrane_session";
    String excSessionIdPropertyName = "membrane_session_id";
    String excMembraneSessionPropertyName = "SESSION";
    String excMembraneSessionIdPropertyName = "SESSION_ID";
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

        if(exc.getProperties().containsKey(excSessionPropertyName))
            memExc.setProperty(excMembraneSessionPropertyName,exc.getProperties().get(excSessionPropertyName));

        SessionManager.Session memSession = sessionManager.getOrCreateSession(memExc);

        if(memExc.getProperty(excMembraneSessionPropertyName) != null)
            exc.getProperties().put(excSessionPropertyName,memExc.getProperty(excMembraneSessionPropertyName));
        if(memExc.getProperty(excMembraneSessionIdPropertyName) != null)
            exc.getProperties().put(excSessionIdPropertyName,memExc.getProperty(excMembraneSessionIdPropertyName));

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

            @Override
            public void removeValue(String key) throws Exception {
                session.getUserAttributes().remove(prefixKey(key));
            }

            private String prefixKey(String key){
                return sessionKeyPrefix + "_" + key;
            }
        } ;
    }

    public void postProcessSession(Exchange exc, com.predic8.membrane.core.exchange.Exchange memExc){
        Object sessionId = exc.getProperties().get(excSessionIdPropertyName);

        if(sessionId != null && exc.getResponse() != null){
            memExc.setProperty(excMembraneSessionIdPropertyName,sessionId);
            sessionManager.postProcess(memExc);
        }


    }
}
