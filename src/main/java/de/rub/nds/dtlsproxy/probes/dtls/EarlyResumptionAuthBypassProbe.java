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
import de.rub.nds.dtlsproxy.exceptions.MissingProofException;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EarlyResumptionAuthBypassProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public EarlyResumptionAuthBypassProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.NO_EARLY_RESUMPTION_IDS,
                executeWithRetries(() -> testEarlyResumptionBypassWithId(report)));
    }

    private TestResult testEarlyResumptionBypassWithId(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server allows to early resumption (auth bypass)");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        WorkflowTrace trace = createEarlyResumptionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "EARLY_RESUMPTION_AUTH_BYPASS");
        return analyzeResult(trace);
    }

    private TestResult analyzeResult(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. Could perform early resumption."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(
                    TestResults.FALSE, "Vulnerable, server allowed early resumption");
        } else {
            LOGGER.debug("Trace did not execute as planned. Could not perform resumption.");
            ProtocolMessage lastMessage = WorkflowTraceResultUtil.getLastReceivedMessage(trace);
            // We are not using the extract proof result method here, because we are have different
            // behavior for CCS...

            // Test if we received an alert message.
            for (ProtocolMessage message : trace.getLastReceivingAction().getReceivedMessages()) {
                if (message instanceof AlertMessage) {
                    LOGGER.debug("Received an Alert message. Client noticed duplicate SKE.");
                    return new DetailedResult<String>(
                            TestResults.TRUE,
                            "Received alert message: " + message.toCompactString());
                }
                if (message instanceof ChangeCipherSpecMessage) {
                    LOGGER.debug("Received a CCS message. Looks very suspicious.");
                    return new DetailedResult<String>(
                            TestResults.PARTIALLY,
                            "Received CCS message: " + message.toCompactString());
                }
            }

            if (executionAttemptsExceeded()) {
                return new DetailedResult<String>(
                        TestResults.TRUE,
                        "Received neither alert nor finished handshake. Last message: "
                                + lastMessage.toCompactString());
            } else {
                throw new MissingProofException();
            }
        }
    }

    /**
     * Creates a trace that performs an incomplete handshake before the certificate verify message
     * has been send/received and then tries to resume with a different client hello. If this is
     * successfull, the CKE message is never authenticated.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<-SH,C,SKE,CR,SHD-| Forward Flight|<-SH,C,SKE,CR,SHD-|
     * |-CERT,CKE,CV,CCS->|    Buffer
     *                    |  -> COPY ->   |
     *                          POP       |-------CERT------>|
     *                         Dynamic    |-------CKE------->|
     *                    |     RESET     |
     *                          SEND      |--------CH------->|
     *                       ReceiveTill  |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createEarlyResumptionTrace(WebRtcPlatformReport report, Config config) {
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
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, true, true));

        trace.addTlsAction(
                new BufferedReceiveAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateMessage(),
                        new ECDHClientKeyExchangeMessage(),
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage()));
        trace.addTlsAction(
                new CopyBufferedMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(
                        ATTACKER_TO_SERVER_CONNECTION)); // This sends the certificate message

        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(new ResetConnectionAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(ATTACKER_TO_SERVER_CONNECTION, new ClientHelloMessage(config)));

        trace.addTlsAction(
                new ReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ChangeCipherSpecMessage()));

        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.SERVER_REQUESTS_CERTIFICATE,
                WebRtcProperties.WANT_TO_TEST_SERVER);
    }
}
