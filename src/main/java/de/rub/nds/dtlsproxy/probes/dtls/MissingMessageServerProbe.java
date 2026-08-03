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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MissingMessageServerProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public MissingMessageServerProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CV,
                executeWithRetries(() -> serverTestMissingCertificateVerify(report)));
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_CV,
                executeWithRetries(() -> serverTestMissingCertificateAndCertificateVerify(report)));
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_EMPTY_SIGNATURE,
                executeWithRetries(
                        () -> serverTestMissingCertificateMessage(report, BytePattern.EMPTY, 0)));
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_ALL_ZERO_SIGNATURE,
                executeWithRetries(
                        () ->
                                serverTestMissingCertificateMessage(
                                        report,
                                        BytePattern.ALL_ZERO,
                                        report.getDefaultSignatureLength())));
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_ALL_FF_SIGNATURE,
                executeWithRetries(
                        () ->
                                serverTestMissingCertificateMessage(
                                        report,
                                        BytePattern.ALL_FF,
                                        report.getDefaultSignatureLength())));
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_EMPTY_CERT,
                executeWithRetries(() -> serverTestEmptyCertificate(report)));
    }

    private TestResult serverTestMissingCertificateVerify(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is noticing that the CertificateVerify message is missing");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createMissingCertificateVerifyTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "MISSING_CERTIFICATE_VERIFY");
        return analyzeResult(trace);
    }

    private TestResult serverTestEmptyCertificate(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server is accepting an empty certificate message");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createEmptyCertificateTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_EMPTY_CERTIFICATE_SERVER");
        return analyzeResult(trace);
    }

    private TestResult serverTestMissingCertificateMessage(
            WebRtcPlatformReport report, BytePattern pattern, int signatureLength) {

        LOGGER.info(
                "Testing if the server is noticing that the Certificate message is missing (Pattern: {}, SignatureLength: {})",
                pattern.name(),
                signatureLength);
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace =
                createMissingCertificateMessageTrace(report, pattern, signatureLength, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_MISSING_CERTIFICATE");
        return analyzeResult(trace);
    }

    private TestResult serverTestMissingCertificateAndCertificateVerify(
            WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is noticing that the Certificate and CertificateVerify message are missing");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createMissingCertificateAndCertificateVerifyTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_MISSING_CERTIFICATE_AND_CERTIFICATE_VERIFY");
        return analyzeResult(trace);
    }

    private TestResult analyzeResult(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. Server did not notice missing message(s)."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server send CCS,FIN and is vulnerable."
                            + AnsiColor.RESET);
            return TestResults.FALSE;
        } else {
            LOGGER.debug(
                    "Trace did not execute as planned. Server noticed missing message(s) and did not complete the handshake.");
            return extractProofResult(trace);
        }
    }

    /**
     * Creates a trace that tests if the server is noticing that the client did not provide a
     * CertificateVerify message and therefore no proof that the client owns the private key.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<---SH Flight-----|    Forward    |<---SH Flight-----|
     * |--[C,CKE,CV],CCS->|  BUFFER Till
     *                    |  -> COPY ->   |
     *                          POP       |----Certificate-->|
     *                       Dynamic Send |-------CKE------->|
     *                          Send      |-------CCS------->|
     *                          Send      |-------FIN------->|
     *                       Receive Till |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createMissingCertificateVerifyTrace(
            WebRtcPlatformReport report, Config config) {
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
                new CopyBufferedMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Certificate

        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    /**
     * Creates a trace that tests if the server is noticing that the client did not provide a
     * certificate & CertificateVerify message and therefore no proof that the client is even
     * authorized.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                       Receive Till |<------SHD--------|
     *                       Dynamic Send |-------CKE------->|
     *                            Send    |-----CCS,FIN----->|
     *                      Receive Till  |<--[NST],CCS,FIN--|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createMissingCertificateAndCertificateVerifyTrace(
            WebRtcPlatformReport report, Config config) {
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
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));

        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    private WorkflowTrace createMissingCertificateMessageTrace(
            WebRtcPlatformReport report, BytePattern pattern, int signatureLength, Config config) {
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
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));

        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage();
        certificateVerify.setSignature(
                createSignatureBytesModifiableVariable(pattern, signatureLength));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        certificateVerify,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    /**
     * Creates a trace that
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                       Receive Till |<------SHD--------|
     *                           Send     |------CERT[0]---->|
     *                           Send     |-------CKE------->|
     *                           Send     |-----CCS,FIN----->|
     *                       Receive Till |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createEmptyCertificateTrace(WebRtcPlatformReport report, Config config) {
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
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        CertificateMessage certificateMessage = new CertificateMessage();
        certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
        trace.addTlsAction(new SendAction(ATTACKER_TO_SERVER_CONNECTION, certificateMessage));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    private ModifiableByteArray createSignatureBytesModifiableVariable(
            BytePattern pattern, int length) {
        switch (pattern) {
            case ALL_FF:
                byte[] data = new byte[length];
                if (length != 0) {
                    Arrays.fill(data, 0, length - 1, (byte) 0xFF);
                }
                return Modifiable.explicit(data);
            case ALL_ZERO:
                return Modifiable.explicit(new byte[length]);
            case EMPTY:
                return Modifiable.explicit(new byte[0]);
            default:
                throw new RuntimeException("Unknown BytePattern");
        }
    }

    private enum BytePattern {
        EMPTY,
        ALL_ZERO,
        ALL_FF
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.SERVER_REQUESTS_CERTIFICATE,
                WebRtcProperties.WANT_TO_TEST_SERVER);
    }
}
