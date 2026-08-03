/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.SingleSideMediaProbe;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Probe that will try to start a renegotiation with the server right after the DTLS handshake */
public class RenegotiateReencryptProbe extends SingleSideMediaProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public RenegotiateReencryptProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext, "SERVER ONLY - RENEGOTIATION", false);
        this.setSuppressErrorMessages(true);
    }

    @Override
    public TraceableConnection mitm(WebRtcPlatformReport report) throws IOException {

        getMediaReport()
                .putAdditionalResult(
                        WebRtcProperties.SERVER_ALLOWS_RENEGOTIATION,
                        new DetailedResult<String>(TestResults.NOT_TESTED_YET));

        // modify the bypass trace to add a renegotiation
        WorkflowTrace trace = getAuthBypassTrace();
        // send Renegotiation CH to Server
        trace.addTlsAction(
                new SendAction(
                        getAuthBypass().getAttackerToServerConnectionAlias(),
                        new ClientHelloMessage()));
        // receive SH
        trace.addTlsAction(
                new ReceiveTillAction(
                        getAuthBypass().getAttackerToServerConnectionAlias(),
                        new ServerHelloDoneMessage()));

        try {
            TraceableConnection connection = super.mitm(report);
            LOGGER.info("Server accepted our renegotiation attempt!");
            getMediaReport()
                    .putAdditionalResult(
                            WebRtcProperties.SERVER_ALLOWS_RENEGOTIATION, DetailedResult.TRUE());
            return connection;
        } catch (RuntimeException e) {
            LOGGER.info("Server rejected our renegotiation attempt");
            getMediaReport()
                    .putAdditionalResult(
                            WebRtcProperties.SERVER_ALLOWS_RENEGOTIATION, DetailedResult.FALSE());
            throw new RuntimeException("Probe finished. Ignore this exception.");
        }
    }
}
