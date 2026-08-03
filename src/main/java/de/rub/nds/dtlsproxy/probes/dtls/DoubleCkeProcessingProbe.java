/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.action.ForwardServerFlightAction;
import de.rub.nds.dtlsproxy.enums.AnsiColor;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteMessageSequenceAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DoubleCkeProcessingProbe extends DtlsProbe {
    private enum SequenceNumber {
        SAME,
        CONTINUOUS
    }

    private static final Logger LOGGER = LogManager.getLogger();

    public DoubleCkeProcessingProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_CONTINUOUS_SQN,
                executeWithRetries(() -> testDoubleCke(report, SequenceNumber.CONTINUOUS)));
        report.putResult(
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_SAME_SQN,
                executeWithRetries(() -> testDoubleCke(report, SequenceNumber.SAME)));
    }

    private TestResult testDoubleCke(WebRtcPlatformReport report, SequenceNumber sequenceNumber) {
        LOGGER.info(
                "Testing if the server (does not) processes unauthenticated CKE messages (SQN={})",
                sequenceNumber.name());
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        WorkflowTrace trace = createDoubleCkeTrace(sequenceNumber, config, report);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "UNAUTHENTICATED_DOUBLE_CKE_" + sequenceNumber.name() + "_SQN");
        return analyzeResult(trace);
    }

    private TestResult analyzeResult(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. DoubleCKE was proccessed."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server send CCS,FIN and is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(
                    TestResults.FALSE, "Vulnerable, server processed unauthenticated CKE message");
        } else {
            LOGGER.debug("Not all actions executed as planned.");
            return extractProofResult(trace);
        }
    }

    /**
     * Create a trace that will send a two CKE messages to test if the server can be tricked to use
     * the wrong public key. If the trace executes as planned, we were able to inject an attacker
     * controlled CKE message. This breaks client authentication.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<---SH Flight-----|    Forward    |<---SH Flight-----|
     * |--C,CKE,CV,CCS--->|    BUFFER
     *                    |  -> COPY ->   |
     *                          POP       |----Certificate-->|
     *                          POP       |-------CKE------->|
     *                          POP       |-------CV-------->|
     *                          Send      |-------CKE_2----->| //SQN Tricks
     *                          Send      |----CCS,FIN------>|
     *                         Receive    |<--[NST],CCS,FIN--|
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client verifies the certificate
     */
    private WorkflowTrace createDoubleCkeTrace(
            SequenceNumber sequenceNumber, Config config, WebRtcPlatformReport report) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        trace.addTlsAction(
                new ForwardMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ClientHelloMessage()));
        trace.addTlsAction(
                new ForwardServerFlightAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, false, true));

        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Certificate
        trace.addTlsAction(
                new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Client Key Exchange
        trace.addTlsAction(
                new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Certificate Verify

        if (sequenceNumber == SequenceNumber.SAME) {
            trace.addTlsAction(
                    new ChangeWriteMessageSequenceAction(ATTACKER_TO_SERVER_CONNECTION, 2));
        }

        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION, createClientKeyExchangeMessage(report)));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new NewSessionTicketMessage(false),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        return trace;
    }

    private ClientKeyExchangeMessage createClientKeyExchangeMessage(WebRtcPlatformReport report) {
        if (report.getDefaultSelectedCipherSuite().getKeyExchangeAlgorithm().isKeyExchangeDhe()) {
            return new DHClientKeyExchangeMessage();
        } else if (report.getDefaultSelectedCipherSuite()
                .getKeyExchangeAlgorithm()
                .isKeyExchangeEcdh()) {
            return new ECDHClientKeyExchangeMessage();
        } else if (report.getDefaultSelectedCipherSuite()
                .getKeyExchangeAlgorithm()
                .isKeyExchangeRsa()) {
            return new RSAClientKeyExchangeMessage();
        } else {
            throw new RuntimeException(
                    "Unsupported key exchange algorithm. Should have been caught earlier.");
        }
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.SERVER_REQUESTS_CERTIFICATE,
                WebRtcProperties.WANT_TO_TEST_SERVER);
    }
}
