package com.ctf.session;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SessionRegistry {

    // sessionId -> username
    private final Map<String, String> sessions = new ConcurrentHashMap<>();

    public void registerSession(String sessionId, String username) {
        sessions.put(sessionId, username);
    }

    public void removeSession(String sessionId) {
        sessions.remove(sessionId);
    }

    public Map<String, String> getActiveSessions() {
        return sessions;
    }
    public boolean isUserActive(String username) {
        return sessions.containsValue(username);
    }
}
