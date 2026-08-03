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
import de.rub.nds.dtlsproxy.packet.ParserUtil;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CallSession {

    private static final Logger LOGGER = LogManager.getLogger();

    private int nextConnectionNumber = 1;

    /**
     * Collection of connections that are to be ignored by the proxy as they do not match the target
     * specs
     */
    private Set<ConnectionEntry> whitelistedEntries = new HashSet<>();

    private final ConnectionConfig config;

    private boolean disableFiltering;

    public CallSession(ConnectionConfig config, boolean disableFiltering) {
        this.config = config;
        this.disableFiltering = disableFiltering;
    }

    /**
     * Registers the connection within the session. It is evaluated if the connection is to be
     * whitelisted or to be processed by the tool. If the connection is to be whitelisted, it is
     * marked as such.
     *
     * @param connection new DTLS connection to register to this call
     * @return {@code true} if the connection is to be analyzed by the proxy, {@code false} if the
     *     connection is whitelisted.
     */
    public synchronized boolean registerConnection(HookedConnection connection) {

        int connectionNr = nextConnectionNumber;
        nextConnectionNumber++;

        if (disableFiltering) {
            LOGGER.trace("Connection is accepted as filtering is disabled for this session.");
            return true;
        }

        if (matchesTargetSpecification(connection, connectionNr, config)) {
            LOGGER.trace("Connection matching our target: {}", connection.getEntry().toString());
            return true;
        } else {
            LOGGER.trace(
                    "Connection not matching target specs." + " Whitelisting {}",
                    connection.getEntry().toString());
            whitelistedEntries.add(connection.getEntry());
            return false;
        }
    }

    /**
     * Returns true if the DTLS connection was deemed not to match the target expectation and marked
     * for whitelisting
     *
     * @param connection
     * @return true if the DTLS connection was deemed not to match the target expectation and marked
     *     for whitelisting
     */
    public boolean isWhitelisted(ConnectionEntry connection) {
        return whitelistedEntries.contains(connection);
    }

    public static boolean matchesTargetSpecification(
            HookedConnection connection, int connectionNumber, ConnectionConfig configToMatch) {

        // match connection nr
        if (configToMatch.getTargetHandshakeNumber() != 0
                && !possiblyInvert(
                        configToMatch.getTargetHandshakeNumber() != connectionNumber,
                        configToMatch.isInvert())) {
            // connection number matching enabled and numbers mismatch
            LOGGER.trace(
                    "Rejecting connection because connection number does not match. "
                            + "This is connection {}, we require a connection of number {}",
                    connectionNumber,
                    configToMatch.getTargetHandshakeNumber());
            return false;
        }

        // match connection CH JA3
        if (configToMatch.getTargetClientHelloJA3() != null) {

            // beware, this assumes at the time of the check, an entire client hello has been
            // received

            // client hello JA3 fingerprint matching enabled
            String ja3 = ParserUtil.getClientHelloJA3(connection);
            if (!possiblyInvert(
                    ja3.equals(configToMatch.getTargetClientHelloJA3()),
                    configToMatch.isInvert())) {
                // JA3 mismatch
                LOGGER.trace(
                        "Rejecting connection because CH JA3s are mismatching\nExpected: {}\nReceived: {}",
                        configToMatch.getTargetClientHelloJA3(),
                        ja3);
                return false;
            }
        }

        // We could exclude mismatching port / ip connections as early as the first STUN comes in
        // But we do so here to keep everything in one place

        // match connection remote IP
        if (configToMatch.getTargetRemoteAddress() != null) {
            // remote target ip specified
            String targetIp = configToMatch.getTargetRemoteAddress();
            String connectionIp = connection.getEntry().getOutboundTargetIp().getHostAddress();
            if (!possiblyInvert(targetIp.equals(connectionIp), configToMatch.isInvert())) {
                LOGGER.trace(
                        "Rejecting connection because remote IP does not match with expectation"
                                + "\nExpected: {}\nReceived: {}",
                        configToMatch.getTargetRemoteAddress(),
                        connection.getEntry().getOutboundTargetIp().getHostAddress());
                return false;
            }
        }

        // match local port
        if (configToMatch.getTargetLocalPort() != 0) {
            // locked local port specified
            if (!possiblyInvert(
                    configToMatch.getTargetLocalPort() != connection.getEntry().getLocalPort(),
                    configToMatch.isInvert())) {
                LOGGER.trace(
                        "Rejecting connecasdtion because local port does not match with expectation"
                                + "\nExpected: {}\nReceived: {}",
                        configToMatch.getTargetLocalPort(),
                        connection.getEntry().getLocalPort());
                return false;
            }
        }

        // match remote port
        if (configToMatch.getTargetRemotePort() != 0) {
            // locked remote port specified
            if (!possiblyInvert(
                    configToMatch.getTargetRemotePort() != connection.getEntry().getRemotePort(),
                    configToMatch.isInvert())) {
                LOGGER.trace(
                        "Rejecting connection because remote port does not match with expectation"
                                + "\nExpected: {}\nReceived: {}",
                        configToMatch.getTargetRemotePort(),
                        connection.getEntry().getRemotePort());
                return false;
            }
        }
        return true;
    }

    private static boolean possiblyInvert(boolean match, boolean invert) {
        return (!invert && match) || (invert && !match);
    }

    public boolean isDisableFiltering() {
        return disableFiltering;
    }

    public void setDisableFiltering(boolean disableFiltering) {
        this.disableFiltering = disableFiltering;
    }

    public int getNextConnectionNumber() {
        return nextConnectionNumber;
    }
}
