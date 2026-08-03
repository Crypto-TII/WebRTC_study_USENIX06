/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.impl;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.RtpProbe;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Probe that checks whether an alert is received from a peer after completing a bypass handshake
 */
public class BypassesProducesAlertProbe extends RtpProbe {

    static final Logger LOGGER = LogManager.getLogger();

    public BypassesProducesAlertProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(
                webrtcExecutionContext,
                "Await alert messages withing the configured timeout after handshake bypass",
                false,
                false);
    }

    @Override
    protected void postDtlsCheck(TraceableConnection dtlsConnection) {
        // empty
    }

    @Override
    public TraceableConnection mitm(WebRtcPlatformReport report) throws IOException {
        getMediaReport()
                .putAdditionalResult(
                        WebRtcProperties.BYPASS_PRODUCED_ALERT,
                        new DetailedResult<String>(TestResults.NOT_TESTED_YET));
        TraceableConnection connection = super.mitm(report);

        // check if Alert found
        WorkflowTrace trace = getAuthBypassTrace();
        if (WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT)) {
            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            LOGGER.info(
                    "Received an alert after handshake bypass completion: {}",
                    message.toCompactString());
            getMediaReport()
                    .putAdditionalResult(
                            WebRtcProperties.BYPASS_PRODUCED_ALERT,
                            new DetailedResult<String>(
                                    TestResults.TRUE, message.toCompactString()));
        } else {
            getMediaReport()
                    .putAdditionalResult(
                            WebRtcProperties.BYPASS_PRODUCED_ALERT, DetailedResult.FALSE());
        }

        return connection;
    }

    @Override
    public WorkflowTrace finalizeBypassTrace(WorkflowTrace authBypassTrace) {

        // wait in case an alert arrives
        AlertMessage postHandshakeClientAlertMessage = new AlertMessage();
        AlertMessage postHandshakeServerAlertMessage = new AlertMessage();
        postHandshakeClientAlertMessage.setRequired(false);
        postHandshakeServerAlertMessage.setRequired(false);
        authBypassTrace.addTlsAction(
                new ReceiveAction(
                        getAuthBypass().getClientToAttackerConnectionAlias(),
                        postHandshakeClientAlertMessage));
        authBypassTrace.addTlsAction(
                new ReceiveAction(
                        getAuthBypass().getAttackerToServerConnectionAlias(),
                        postHandshakeServerAlertMessage));

        return authBypassTrace;
    }
}
