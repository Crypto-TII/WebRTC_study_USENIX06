/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteMessageSequenceAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DoubleSkeProcessingProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public DoubleSkeProcessingProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_CONTINUOUS_SQN,
                executeWithRetries(() -> testDoubleSke(report, SequenceNumber.CONTINUOUS)));
        report.putResult(
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_SAME_SQN,
                executeWithRetries(() -> testDoubleSke(report, SequenceNumber.SAME)));
    }

    private TestResult testDoubleSke(WebRtcPlatformReport report, SequenceNumber sequenceNumber) {
        LOGGER.info(
                "Testing if the client is (not) processing a duplicate SKE message without verifing the second signature");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        WorkflowTrace trace = createDoubleSkeTrace(config, sequenceNumber, report);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "UNAUTHENTICATED_DOUBLE_SKE_" + sequenceNumber.name() + "_SQN");
        return analyzeResults(trace);
    }

    private TestResult analyzeResults(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. DoubleSKE was proccessed."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(
                    TestResults.FALSE, "Vulnerable, client processed unauthenticated SKE message");
        } else {
            LOGGER.debug("Trace did not execute as planned. Client is not using our double SKE.");
            ProtocolMessage lastMessage = WorkflowTraceResultUtil.getLastReceivedMessage(trace);

            // Test if we received an alert message. We then know that the peer did notice our trick
            for (ProtocolMessage message : trace.getLastReceivingAction().getReceivedMessages()) {
                if (message instanceof AlertMessage) {
                    LOGGER.debug("Received an Alert message. Client noticed duplicate SKE.");
                    return new DetailedResult<String>(
                            TestResults.TRUE,
                            "Received alert message: " + message.toCompactString());
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
     * Creates a Trace that tries to inject an additional SKE message into the trace in the hopes
     * that the client does not verify the second signature. If it accepts this SKE message and uses
     * the key to compute the master secret, the client is vulnerable to a MitM attack.
     *
     * <p>There are two variants we have to consider here. One where the peers naturally negotiate
     * an ephemeral cipher suite and one where we have to help them to do so.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward
     *                      or Manipulate |---ClientHello--->|
     *                       BUFFER Till  |<------SHD--------|
     *                    |  <- COPY <-   |
     * |<--ServerHello----|     POP
     * |<--Certificate----|     POP
     * |<------SKE--------|     POP
     * |<------SKE_2------|     SEND // SQN Tricks
     * |<-------CR--------|     SEND // SQN Tricks
     * |<-ServerHelloDone-|     SEND // SQN Tricks
     * |---Certificate--->|    Receive
     * |-------CKE------->|    Receive
     * |-------CV-------->|    Receive
     * |-------CCS------->|    Receive
     * |-------FIN------->|    Receive
     * </pre>
     *
     * @param config
     * @param sequenceNumber
     * @param report
     */
    private WorkflowTrace createDoubleSkeTrace(
            Config config, SequenceNumber sequenceNumber, WebRtcPlatformReport report) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        CipherSuite cipherSuite = report.getDefaultSelectedCipherSuite();
        if (cipherSuite != null && !cipherSuite.isEphemeral()) {
            // We need to enforce ephemeral cipher suites
            // TODO Manipulate lists
            // TODO Set 'cipherSuite' variable also to something ephemeral
            throw new UnsupportedOperationException("Not yet implemented");
        } else {
            trace.addTlsAction(
                    new ForwardMessagesAction(
                            CLIENT_TO_ATTACKER_CONNECTION,
                            ATTACKER_TO_SERVER_CONNECTION,
                            new ClientHelloMessage()));
        }

        final boolean serverRequestsCert =
                report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE) == TestResults.TRUE;

        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage();
        final ServerHelloDoneMessage serverHelloDoneMessage = new ServerHelloDoneMessage();
        certificateRequestMessage.setRequired(serverRequestsCert);

        trace.addTlsAction(
                new BufferedReceiveAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        createServerKeyExchangeMessage(report),
                        certificateRequestMessage,
                        serverHelloDoneMessage));
        trace.addTlsAction(
                new CopyBuffersAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));

        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // ServerHello
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Certificate
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // original SKE

        if (sequenceNumber == SequenceNumber.SAME) {
            trace.addTlsAction(
                    new ChangeWriteMessageSequenceAction(CLIENT_TO_ATTACKER_CONNECTION, 2));
        }

        // send inserted SKE
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION, createServerKeyExchangeMessage(report)));

        if (serverRequestsCert) {
            trace.addTlsAction(
                    new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new CertificateRequestMessage()));
        }
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloDoneMessage()));

        // --- expect client to finish the handshake ---
        final CertificateMessage clientCertificateMessage = new CertificateMessage();
        final ClientKeyExchangeMessage clientKeyExchangeMessage =
                createClientKeyExchangeMessage(report);
        final CertificateVerifyMessage clientCertificateVerifyMessage =
                new CertificateVerifyMessage();
        final ChangeCipherSpecMessage clientChangeCipherSpecMessage = new ChangeCipherSpecMessage();
        final FinishedMessage clientFinishedMessage = new FinishedMessage();
        clientCertificateMessage.setRequired(serverRequestsCert);
        clientCertificateVerifyMessage.setRequired(serverRequestsCert);
        trace.addTlsAction(
                new ReceiveAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        clientCertificateMessage,
                        clientKeyExchangeMessage,
                        clientCertificateVerifyMessage,
                        clientChangeCipherSpecMessage,
                        clientFinishedMessage));
        // -----------------------------------------------
        return trace;
    }

    private ServerKeyExchangeMessage createServerKeyExchangeMessage(WebRtcPlatformReport report) {
        if (report.getDefaultSelectedCipherSuite().getKeyExchangeAlgorithm().isKeyExchangeDhe()) {
            return new DHEServerKeyExchangeMessage();
        } else if (report.getDefaultSelectedCipherSuite()
                .getKeyExchangeAlgorithm()
                .isKeyExchangeEcdh()) {
            return new ECDHEServerKeyExchangeMessage();
        } else if (report.getDefaultSelectedCipherSuite()
                .getKeyExchangeAlgorithm()
                .isKeyExchangeRsa()) {
            return null;
        } else {
            throw new RuntimeException(
                    "Unsupported key exchange algorithm. Should have been caught earlier.");
        }
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
                WebRtcProperties.COMPLETELY_FUNCTIONAL, WebRtcProperties.WANT_TO_TEST_CLIENT);
    }

    private enum SequenceNumber {
        SAME,
        CONTINUOUS
    }
}
