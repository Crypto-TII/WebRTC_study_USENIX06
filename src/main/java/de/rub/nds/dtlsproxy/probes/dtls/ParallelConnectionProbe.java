/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.ProxiedConnectionProvider;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ParallelConnectionProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Threads to run, expecting a DTLS connection */
    private static final int PARALLEL_CONNECTION_TRIES = 10;

    /** The time in ms to wait for DTLS connections */
    private static final int TIMEOUT = 8000;

    public ParallelConnectionProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
        super.setSilentConnectionFetch(true);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {

        ThreadGroup threadGroup = new ThreadGroup("Connections");

        if (getConnectionProvider() instanceof ProxiedConnectionProvider) {
            // wait for last session to end so we don't catch a connection from the last
            // (Probes that use fetchConnection() will use the Provider for that)
            ((ProxiedConnectionProvider) getConnectionProvider()).waitForSessionEnd();
        }

        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        // init traces
        WorkflowTrace[] traces = new WorkflowTrace[PARALLEL_CONNECTION_TRIES];
        for (int i = 0; i < PARALLEL_CONNECTION_TRIES; i++) {
            traces[i] = createTrace(config, report);
        }

        // kick off connection threads
        for (int i = 0; i < PARALLEL_CONNECTION_TRIES; i++) {
            int finalI = i;
            new Thread(
                            threadGroup,
                            () -> this.trySingleConnection(config, traces[finalI], finalI),
                            "Connection " + i)
                    .start();
        }

        // start booter if there is any, be aware this will not reattempt on failure
        if (getConnectionProvider() instanceof ProxiedConnectionProvider) {
            // this provider connection details, which will get in the way here
            ((ProxiedConnectionProvider) getConnectionProvider()).prepareNextConnection(true);
        } else {
            getConnectionProvider().prepareNextConnection();
        }

        // wait for a thread to catch the first DTLS connection
        synchronized (this) {
            LOGGER.debug("Waiting for the first DTLS connection (beware, this won't time out)");
            try {
                this.wait();
            } catch (InterruptedException e) {
                return;
            }
        }

        try {
            Thread.sleep(TIMEOUT);
        } catch (InterruptedException ignored) {
        }

        threadGroup.interrupt();

        // count successful connections
        int connectionsFound = 0;
        for (int i = 0; i < PARALLEL_CONNECTION_TRIES; i++) {
            if (traces[i].allActionsExecuted() && traces[i].executedAsPlanned()) {
                connectionsFound++;
            }
        }

        LOGGER.info("The application established {} DTLS connections", connectionsFound);
        report.setDtlsSessionsPerCall(connectionsFound);
        // freed back information into session manager to better plan next resets
        if (getSessionManager() != null) {
            getSessionManager().setDtlsSessionsPerCall(connectionsFound);
        }
    }

    private void trySingleConnection(Config config, WorkflowTrace trace, int num) {

        TraceableConnection connection;

        try {
            connection = createConnection(config, trace);
        } catch (Exception e) {
            // ignore errors caused by failed connection fetch
            return;
        }

        // wake up main thread, to start the timer for the probe as we have found the first
        // connection
        synchronized (this) {
            this.notify();
        }

        connection.getConnectionInterface().setFilterActive(false);
        execute(connection, "SINGLE_CONNECTION_" + num);
    }

    /**
     * Creates a trace that assumes all DTLS is forwarded by the filter, but also send to DTLS
     * processing. The purpose is to make CH, SH, and certificates available for post analyzing
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Receive
     *                         Receive    |<---SH Flight-----|
     * |-------CCS------->|  ReceiveTill
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     */
    private static WorkflowTrace createTrace(Config config, WebRtcPlatformReport report) {

        config.setFinishWithCloseNotify(false);

        WorkflowTrace trace = TraceUtil.createTrace(config);

        // detect CH only. This is sufficient, as we setFilterActive on all connections, so the
        // application we occupy the connection on both sides instead of trying is again on another
        // transport

        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));

        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(WebRtcProperties.COMPLETELY_FUNCTIONAL);
    }
}
