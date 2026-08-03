/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import de.rub.nds.dtlsproxy.config.ConnectionConfig;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionManager {

    private static final int MAX_BLOCKED_ENTRIES = 10;

    private static final Logger LOGGER = LogManager.getLogger();

    private final Map<ConnectionEntry, HookedConnection> connectionMap;

    private final Stack<HookedConnection> freshConnectionsStack;

    private final Object lock = new Object();

    private final ConnectionConfig connectionConfig;

    private CallSession currentSession;

    /**
     * Amount of DTLS handshakes the app performs in a single call. Default to 0 until it is
     * determined by a probe. Hence 0 is reserved for an unknown number of dtls handshakes.
     */
    private int dtlsSessionsPerCall;

    /**
     * We always blacklist the last N connections from preventing used connections to show up as
     * fresh connection if multiple connections are used at the same. The Blacklist is spanning
     * session to specifically discard packets from recently released connections
     */
    private Queue<ConnectionEntry> blockedEntries = new LinkedList<>();

    /**
     * Assumed sessions per call, incrementing is not session was found in a scenario where the
     * actual amount of total dtlsSessionsPerCall is yet unknown.
     */
    private int dtlsSessionsPerCallAssumption = 1;

    public SessionManager(ConnectionConfig connectionConfig) {
        connectionMap = new ConcurrentHashMap<>();
        freshConnectionsStack = new Stack<>();
        this.connectionConfig = connectionConfig;
    }

    public boolean isConnectionMapEmpty() {
        return connectionMap.isEmpty();
    }

    public boolean isBlacklisted(ConnectionEntry entry) {
        return blockedEntries.contains(entry);
    }

    public boolean isWhitelisted(ConnectionEntry entry) {
        if (currentSession != null) {
            return currentSession.isWhitelisted(entry);
        }
        // TODO whats better: whitelist or process too early DTLS connections?
        return true;
    }

    public synchronized void register(HookedConnection connection) {

        LOGGER.debug("Registering new connection: {}", connection.getEntry());

        // asses whether to notify a waiting analysis thread about this connection or to whitelist
        // it
        // depending on whether this connection matches specified target properties f.e. CH JA3

        boolean connectionFound = currentSession.registerConnection(connection);

        connectionMap.put(connection.getEntry(), connection);
        blockedEntries.add(connection.getEntry());
        if (blockedEntries.size() > MAX_BLOCKED_ENTRIES) {
            blockedEntries.poll();
        }
        if (connectionFound) {
            // notify listeners of successful connection match
            synchronized (lock) {
                freshConnectionsStack.push(connection);
                lock.notify();
            }
            LOGGER.debug("Notified waiting threads about new DTLS connection");
        } else {
            LOGGER.debug("Skipping connection because not deemed fitting");

            if (requireSessionResetForNextConnection()) {
                LOGGER.trace(
                        "Out of connections in this session. Notifying threads to start a new one");

                if (dtlsSessionsPerCall == 0) {
                    // failed to fetch connection, when connection count per call unknown.
                    // Try to fetch fitting connection in a larger connection span
                    LOGGER.trace(
                            "Increasing assumed dtls connections per call to {}",
                            (dtlsSessionsPerCallAssumption + 1));
                    dtlsSessionsPerCallAssumption++;
                }

                // we need a reset
                synchronized (lock) {
                    // avoid threading issues to the connection stack by draining...
                    drainConnections();
                    lock.notify();
                }
            }
        }
    }

    /**
     * Assesses whether the current session needs to be terminated and a new one be started or if a
     * matching connection is to be expected from the current session in the future
     */
    private boolean requireSessionResetForNextConnection() {

        if (dtlsSessionsPerCall == 0) {
            // actual amount of dtls sessions per call unknown
            // use assumed / incremented amount as indicator
            return dtlsSessionsPerCallAssumption + 1 <= currentSession.getNextConnectionNumber();
        }

        return dtlsSessionsPerCall + 1 <= currentSession.getNextConnectionNumber();
    }

    public boolean isRegistered(ConnectionEntry entry) {
        return connectionMap.containsKey(entry);
    }

    /**
     * May return null
     *
     * @param entry
     * @return
     */
    public synchronized HookedConnection getConnection(ConnectionEntry entry) {
        return connectionMap.get(entry);
    }

    public void drainConnections() {
        // clear waiting connection matches
        freshConnectionsStack.clear();

        // TODO maybe also blacklist all latest connections. This would help with packages to dead
        // connections.
        //  But we need to keep a history for that.
    }

    /**
     * Prepares the next session and sets whether it should match the handshake number with the ohe
     * specified
     *
     * @param disableFiltering whether to wildcard match handshake numbers instead of filtering them
     */
    public synchronized void prepareNext(boolean disableFiltering) {

        // overwrite handshake number check if no handshake count has been specified yet
        if (dtlsSessionsPerCallUnknown()) {
            LOGGER.trace(
                    "Preparing new Session to ignore handshake numbers, as we don't know how many handshakes"
                            + " we are going to see yet.");
            disableFiltering = true;
        }

        currentSession = new CallSession(connectionConfig, disableFiltering);
    }

    public HookedConnection fetchFreshConnection() throws ConnectionNotRetrievableException {
        synchronized (lock) {
            if (!freshConnectionsStack.isEmpty()) {
                // connection ready already
                return freshConnectionsStack.pop();
            }

            // no connection ready, wait till wake up from filter
            LOGGER.debug("No DTLS connection on the stack, waiting");
            try {
                lock.wait();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            if (!freshConnectionsStack.isEmpty()) {
                // connection found
                return freshConnectionsStack.pop();
            } else {
                // woken up without a connection available
                // --> Assume connection not possible to be retrieved and throw error
                throw new ConnectionNotRetrievableException(
                        "Expecting no more matching connections in this session");
            }
        }
    }

    public boolean dtlsSessionsPerCallUnknown() {
        return dtlsSessionsPerCall == 0;
    }

    public void setDtlsSessionsPerCall(int dtlsSessionsPerCall) {
        this.dtlsSessionsPerCall = dtlsSessionsPerCall;
        if (dtlsSessionsPerCall < connectionConfig.getTargetHandshakeNumber()) {
            throw new RuntimeException(
                    "Handshake number filter specified out of reach. Filtering for HS nr "
                            + connectionConfig.getTargetHandshakeNumber()
                            + ", but a session has only "
                            + dtlsSessionsPerCall);
        }
    }

    public ConnectionConfig getConnectionConfig() {
        return connectionConfig;
    }

    public int getDtlsSessionsPerCall() {
        return dtlsSessionsPerCall;
    }

    public synchronized void release(HookedConnection connection) {
        connectionMap.remove(connection.getEntry());
    }
}
