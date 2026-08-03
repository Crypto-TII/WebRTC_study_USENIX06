/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.packet.PacketCaptureController;
import de.rub.nds.dtlsproxy.post.PostAnalyzer;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.provider.ConnectionProvider;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Probe {

    private static final Logger LOGGER = LogManager.getLogger();

    private final WebrtcExecutionContext webrtcExecutionContext;

    /**
     * If true, the probe will not call the connection provider to create a fully fledged connection
     * (f.e. a new voice call) but rather to take just the next DTLS connection appearing on the
     * network stack
     */
    private boolean silentConnectionFetch = false;

    protected Probe(WebrtcExecutionContext webrtcExecutionContext) {
        this.webrtcExecutionContext = webrtcExecutionContext;
    }

    /**
     * Performs the test
     *
     * @param report
     */
    public void test(WebRtcPlatformReport report) {
        startCapture(this.getClass().getSimpleName());
        runChecks(report);
        endCapture(this.getClass().getSimpleName());
    }

    protected abstract void runChecks(WebRtcPlatformReport report);

    protected TraceableConnection createConnection(
            Config config,
            WorkflowTrace trace,
            String clientToAttackerConnectionAlias,
            String attackerToServerConnectionAlias) {
        ConnectionInterface dtlsConnection =
                silentConnectionFetch
                        ? webrtcExecutionContext.getConnectionProvider().nextConnection()
                        : webrtcExecutionContext.getConnectionProvider().createConnection();

        if (dtlsConnection.isUsingTurn()) {
            LOGGER.debug(
                    "Enabling TURN: {}:{}",
                    dtlsConnection.getTurnMappedConnectionIp(),
                    dtlsConnection.getTurnMappedConnectionPort());
            config.setDefaultLayerConfiguration(StackConfiguration.DTLS_OVER_TURN);
            config.getIceConfig().setDefaultAddress(dtlsConnection.getTurnMappedConnectionIp());
            config.getIceConfig().setDefaultPort(dtlsConnection.getTurnMappedConnectionPort());
        }
        State state = new State(config, trace);
        dtlsConnection.initTransportHandlers(
                clientToAttackerConnectionAlias, attackerToServerConnectionAlias, state);
        if (dtlsConnection.getCreatedFromFilterDirection() == FilterDirection.INBOUND) {
            // The local application send the first DTLS message - so its ice connection end type is
            // client
            LOGGER.debug("Creating connection from inbound direction");
            state.getContext(clientToAttackerConnectionAlias)
                    .getIceContext()
                    .setIceConnectionEndType(ConnectionEndType.SERVER);
            state.getContext(attackerToServerConnectionAlias)
                    .getIceContext()
                    .setIceConnectionEndType(ConnectionEndType.CLIENT);
        } else {
            // The remote application send the first DTLS message - so its ice connection end type
            // is client
            LOGGER.debug("Creating connection from outbound direction");
            state.getContext(clientToAttackerConnectionAlias)
                    .getIceContext()
                    .setIceConnectionEndType(ConnectionEndType.SERVER);
            state.getContext(attackerToServerConnectionAlias)
                    .getIceContext()
                    .setIceConnectionEndType(ConnectionEndType.CLIENT);
        }
        return new TraceableConnection(state, dtlsConnection);
    }

    public boolean isSilentConnectionFetch() {
        return silentConnectionFetch;
    }

    /**
     * Set wether connection should not be created by f.e. starting a new call but rather by picking
     * the next DTLS connection available
     *
     * @param silentConnectionFetch
     */
    public void setSilentConnectionFetch(boolean silentConnectionFetch) {
        this.silentConnectionFetch = silentConnectionFetch;
    }

    protected ConnectionProvider getConnectionProvider() {
        return webrtcExecutionContext.getConnectionProvider();
    }

    protected ProxyConfiguration getProxyConfiguration() {
        return webrtcExecutionContext.getProxyConfiguration();
    }

    protected SessionManager getSessionManager() {
        return webrtcExecutionContext.getSessionManager();
    }

    protected PostAnalyzer getPostAnalyzer() {
        return webrtcExecutionContext.getPostAnalyzer();
    }

    protected List<AliasedConnection> createConnectionList(Config config) {
        List<AliasedConnection> aliasedConnections = new LinkedList<>();
        aliasedConnections.add(config.getDefaultClientConnection());
        aliasedConnections.add(config.getDefaultServerConnection());
        return aliasedConnections;
    }

    protected abstract List<WebRtcProperties> getRequiredProperties();

    public boolean isTestApplicable(WebRtcPlatformReport report) {
        for (WebRtcProperties property : getRequiredProperties()) {
            if (report.getResult(property) != TestResults.TRUE) {
                return false;
            }
        }
        return true;
    }

    protected void startCapture(String title) {

        if (getProxyConfiguration().getRecordingDirectory() == null) {
            return;
        }

        LOGGER.trace("Starting recording {}", title);
        PacketCaptureController.startCapture(
                getProxyConfiguration().getRecordingDirectory(), title);
    }

    protected void endCapture(String title) {

        if (getProxyConfiguration().getRecordingDirectory() == null) {
            return;
        }

        LOGGER.trace("Stopping recording {}", title);
        PacketCaptureController.stopCapture(title);
    }
}
