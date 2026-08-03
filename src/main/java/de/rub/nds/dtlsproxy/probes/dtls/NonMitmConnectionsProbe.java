/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.provider.ProxiedConnectionProvider;
import de.rub.nds.dtlsproxy.provider.proxy.CallSession;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This probe does not MitM connections, but instead just forwards the data and creates a recording
 * of the connection. If
 */
public class NonMitmConnectionsProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int NUMBER_OF_CONNECTIONS = 10;
    private static final long SAMPLE_DURATION_IN_MS = 20000;

    private static final int REEXECUTION_COUNTER = 6;

    private int targetConnectionObservedInitiatedByInbound = 0;
    private int targetConnectionObservedInitiatedByOutbound = 0;

    public NonMitmConnectionsProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        LOGGER.info("Observing " + REEXECUTION_COUNTER + " connections without MitM");
        try {
            HashMap<PacketType, Integer> protocolsObservedInboundSum = new HashMap<>();
            HashMap<PacketType, Integer> protocolsObservedOutboundSum = new HashMap<>();

            int[] observedTotalHandshakes = new int[REEXECUTION_COUNTER];

            for (int i = 0; i < REEXECUTION_COUNTER; i++) {

                ThreadGroup threadGroup = new ThreadGroup("Connections");

                if (getConnectionProvider() instanceof ProxiedConnectionProvider) {
                    // wait for last session to end so we don't catch a connection from the last
                    // (Probes that use fetchConnection() will use the Provider for that)
                    ((ProxiedConnectionProvider) getConnectionProvider()).waitForSessionEnd();
                }
                startCapture("NORMAL_CONNECTION_" + i);

                // start booter if there is any, be aware this will not reattempt on failure
                if (getConnectionProvider() instanceof ProxiedConnectionProvider) {
                    // this provider connection details, which will get in the way here
                    ((ProxiedConnectionProvider) getConnectionProvider())
                            .prepareNextConnection(true);
                } else {
                    getConnectionProvider().prepareNextConnection();
                }

                ConnectionInterface[] connections = new ConnectionInterface[NUMBER_OF_CONNECTIONS];
                List<Integer> handshakeOrder = new LinkedList<>();
                for (int j = 0; j < NUMBER_OF_CONNECTIONS; j++) {
                    // fetch / forward connections in parallel
                    int finalJ = j;
                    new Thread(
                                    threadGroup,
                                    () -> {
                                        try {
                                            LOGGER.trace("waiting  for connection");
                                            connections[finalJ] =
                                                    getConnectionProvider().nextConnection();
                                            LOGGER.trace(
                                                    "connection found: {}", connections[finalJ]);
                                            handshakeOrder.add(finalJ);
                                            connections[finalJ].setFilterActive(false);
                                        } catch (RuntimeException e) {
                                            // ignore InterruptedException
                                        }
                                    },
                                    "Connection " + j)
                            .start();
                }

                Thread.sleep(SAMPLE_DURATION_IN_MS);

                threadGroup.interrupt();
                endCapture("NORMAL_CONNECTION_" + i);

                targetConnectionObservedInitiatedByInbound = 0;
                targetConnectionObservedInitiatedByOutbound = 0;

                for (int j = 0; j < NUMBER_OF_CONNECTIONS; j++) {
                    if (connections[j] == null) {
                        continue;
                    }
                    collectObservedProtocols(
                            connections[j],
                            protocolsObservedInboundSum,
                            protocolsObservedOutboundSum);
                    collectObservedHandshakeDirections(
                            connections[j], handshakeOrder.indexOf(j) + 1);
                    observedTotalHandshakes[i]++;
                }

                if (observedTotalHandshakes[i] == 0) {
                    LOGGER.warn("No handshake was observed for connection {}", i);
                    LOGGER.error("Provider deemed non functional");
                    report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, false);
                    report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, false);
                    break;
                }
            }
            if (targetConnectionObservedInitiatedByOutbound == 0
                    && targetConnectionObservedInitiatedByInbound == 0) {
                LOGGER.warn(
                        "No connection filter matching handshake was observed for connection. Adjust filter or try again.");
                LOGGER.error("Provider deemed non functional");
                report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, false);
                report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, false);
            }

            setObservedProtocols(report, protocolsObservedInboundSum, protocolsObservedOutboundSum);
            setObservedHandshakeDirections(report);
            setObservedHandshakeCounts(report, observedTotalHandshakes);

        } catch (Exception ex) {
            report.putResult(
                    WebRtcProperties.CLIENT_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, ex.getMessage()));
            report.putResult(
                    WebRtcProperties.COMPLETELY_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, ex.getMessage()));
            report.putResult(
                    WebRtcProperties.PROVIDER_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, ex.getMessage()));
            LOGGER.warn("Could not execute test", ex);
            if (ex.getCause() instanceof TimeoutException) {
                LOGGER.trace("Client timeout threshold exceeded. Did not receive ClientHello.");
            }
        }
    }

    /**
     * Adds the counts of packets ob observed protocols from the hooked connection to the sum maps
     */
    private void collectObservedProtocols(
            ConnectionInterface connection,
            HashMap<PacketType, Integer> protocolsObservedInboundSum,
            HashMap<PacketType, Integer> protocolsObservedOutboundSum) {

        if (!(connection instanceof HookedConnection)) {
            return;
        }

        HookedConnection hookedConnection = (HookedConnection) connection;

        for (PacketType type : hookedConnection.getPacketCountsInbound().keySet()) {
            protocolsObservedInboundSum.merge(
                    type, hookedConnection.getPacketCountsInbound().get(type), Integer::sum);
        }
        for (PacketType type : hookedConnection.getPacketCountsOutbound().keySet()) {
            protocolsObservedOutboundSum.merge(
                    type, hookedConnection.getPacketCountsOutbound().get(type), Integer::sum);
        }
    }

    private void collectObservedHandshakeDirections(
            ConnectionInterface connection, int handshakeNumber) {

        if (connection instanceof HookedConnection) {
            if (!CallSession.matchesTargetSpecification(
                    ((HookedConnection) connection),
                    handshakeNumber,
                    getSessionManager().getConnectionConfig())) {
                // do not count connections that do not match the filtering specification
                return;
            }
        }

        if (connection.isInboundTheDtlsClient()) {
            targetConnectionObservedInitiatedByInbound++;
        } else {
            targetConnectionObservedInitiatedByOutbound++;
        }
    }

    /** Averages packet counts and sets the result in the report */
    private void setObservedProtocols(
            WebRtcPlatformReport report,
            HashMap<PacketType, Integer> protocolsObservedInboundSum,
            HashMap<PacketType, Integer> protocolsObservedOutboundSum) {
        HashMap<PacketType, Integer> protocolsObservedInbound = new HashMap<>();
        for (PacketType type : protocolsObservedInboundSum.keySet()) {
            protocolsObservedInbound.put(
                    type,
                    (protocolsObservedInboundSum.get(type) + NUMBER_OF_CONNECTIONS - 1)
                            / NUMBER_OF_CONNECTIONS);
        }
        report.setProtocolsObservedInbound(protocolsObservedInbound);

        HashMap<PacketType, Integer> protocolsObservedOutbound = new HashMap<>();
        for (PacketType type : protocolsObservedOutboundSum.keySet()) {
            protocolsObservedOutbound.put(
                    type,
                    (protocolsObservedOutboundSum.get(type) + NUMBER_OF_CONNECTIONS - 1)
                            / NUMBER_OF_CONNECTIONS);
        }
        report.setProtocolsObservedOutbound(protocolsObservedOutbound);
    }

    private void setObservedHandshakeDirections(WebRtcPlatformReport report) {
        if (targetConnectionObservedInitiatedByInbound == 0
                && targetConnectionObservedInitiatedByOutbound > 0) {
            // the remote party has always initiated the handshake
            report.putResult(WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, false);
            if (getProxyConfiguration().isOnlyTestLocal()) {
                LOGGER.info(
                        "Observed handshakes to be initiated by the remote party only, restricting test set to server probes");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.FALSE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
            } else if (getProxyConfiguration().isOnlyTestRemote()) {
                LOGGER.info(
                        "Observed handshakes to be initiated by the remote party only, restricting test set to client probes");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.FALSE);
            } else {
                LOGGER.info(
                        "Observed handshakes to be initiated by the remote party only, test set restriction possible, but not enabled");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
            }
        } else if (targetConnectionObservedInitiatedByOutbound == 0
                && targetConnectionObservedInitiatedByInbound > 0) {
            // the remote party was always the handshake server
            report.putResult(WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, true);
            if (getProxyConfiguration().isOnlyTestLocal()) {
                LOGGER.info(
                        "Observed handshakes to be initiated by the local party only, restricting test set to client probes");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.FALSE);
            } else if (getProxyConfiguration().isOnlyTestRemote()) {
                LOGGER.info(
                        "Observed handshakes to be initiated by the local party only, restricting test set to server probes");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.FALSE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
            } else {
                LOGGER.info(
                        "Observed handshakes to be initiated by the local party only, test set restriction possible, but not enabled");
                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
            }
        } else if (targetConnectionObservedInitiatedByInbound > 0
                && targetConnectionObservedInitiatedByOutbound > 0) {
            // handshake initiation is mixed
            LOGGER.info("Observed handshakes to be initiated by varying parties");
            report.putResult(
                    WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, TestResults.PARTIALLY);

            report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
            report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
        } else {
            LOGGER.error(
                    "Could not determine handshake initiation direction: No handshakes observed");
            report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.FALSE);
            report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.FALSE);
            report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.FALSE);
        }
    }

    private void setObservedHandshakeCounts(
            WebRtcPlatformReport report, int[] observedTotalHandshakes) {

        // extract maximum handshake count
        int maxHandshakes = 0;
        for (int i = 0; i < observedTotalHandshakes.length; i++) {
            if (observedTotalHandshakes[i] > maxHandshakes) {
                maxHandshakes = observedTotalHandshakes[i];
            }
        }

        for (int i = 0; i < observedTotalHandshakes.length; i++) {
            if (observedTotalHandshakes[i] != maxHandshakes) {
                // propably a handshake we did not manage to catch because the user did not click
                // through the call quick enough
                LOGGER.warn(
                        "Handshake count for connection {} is not equal to the highest handshake count observed: {}, applying max handshakes for further profiling.",
                        i,
                        maxHandshakes);
            }
        }

        LOGGER.info("Observed application to perform {} handshakes per session", maxHandshakes);
        getSessionManager().setDtlsSessionsPerCall(maxHandshakes);
        report.setDtlsSessionsPerCall(maxHandshakes);

        if (maxHandshakes > 0) {
            report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, true);
        }
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return new LinkedList<>();
    }
}
