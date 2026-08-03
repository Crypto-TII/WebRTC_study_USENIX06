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
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopBufferedMessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureVerificationProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureVerificationProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        TestResult invalidSkeSignature = TestResults.NOT_TESTED_YET;
        TestResult emptySkeSignature = TestResults.NOT_TESTED_YET;
        TestResult noSkeSignature = TestResults.NOT_TESTED_YET;
        TestResult invalidCvSignature = TestResults.NOT_TESTED_YET;
        TestResult emptyCvSignature = TestResults.NOT_TESTED_YET;
        TestResult noCvSignature = TestResults.NOT_TESTED_YET;
        if (report.getDefaultSelectedCipherSuite() == null) {
            LOGGER.warn("DefaultSelectedCipherSuite is not known, skipping test");
            return;
        }
        if (report.getResult(WebRtcProperties.WANT_TO_TEST_CLIENT) == TestResults.TRUE) {
            if (report.getDefaultSelectedCipherSuite().isEphemeral()) {
                invalidSkeSignature =
                        executeWithRetries(() -> testServerKeyExchangeSignature(report));
                emptySkeSignature =
                        executeWithRetries(() -> testServerKeyExchangeEmptySignature(report));
                noSkeSignature =
                        executeWithRetries(() -> testServerKeyExchangeWithoutSignature(report));
            } else {
                invalidSkeSignature = TestResults.CANNOT_BE_TESTED;
                emptySkeSignature = TestResults.CANNOT_BE_TESTED;
                noSkeSignature = TestResults.CANNOT_BE_TESTED;
            }
        }
        if (report.getResult(WebRtcProperties.WANT_TO_TEST_SERVER) == TestResults.TRUE) {

            if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE)
                    == TestResults.TRUE) {
                invalidCvSignature =
                        executeWithRetries(() -> testCertificateVerifySignature(report));
                emptyCvSignature =
                        executeWithRetries(() -> testCertificateVerifyEmptySignature(report));
                noCvSignature =
                        executeWithRetries(() -> testCertificateVerifyMissingSignature(report));
            } else {
                invalidCvSignature = TestResults.CANNOT_BE_TESTED;
                emptyCvSignature = TestResults.CANNOT_BE_TESTED;
                noCvSignature = TestResults.CANNOT_BE_TESTED;
            }
        }
        report.putResult(WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE, invalidCvSignature);
        report.putResult(WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE, emptyCvSignature);
        report.putResult(WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE, noCvSignature);
        report.putResult(WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE, invalidSkeSignature);
        report.putResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE, emptySkeSignature);
        report.putResult(WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE, noSkeSignature);
    }

    public TestResult testCertificateVerifySignature(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is verifying the certificate verify message it receives");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        WorkflowTrace trace = createInvalidSignatureCvTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_CERTIFICATE_VERIFY_SIGNATURE");
        return analyzeResult(trace);
    }

    public TestResult testCertificateVerifyEmptySignature(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is does accept new byte[0] as the signature in the CV message");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);
        WorkflowTrace trace = createEmptyCvTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_CERTIFICATE_VERIFY_EMPTY_SIGNATURE");
        return analyzeResult(trace);
    }

    public TestResult testCertificateVerifyMissingSignature(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is does accept CV message that does not contain a signature (or sig length field)");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);
        WorkflowTrace trace = createMissingSignatureCvTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_CERTIFICATE_VERIFY_MISSING_SIGNATURE");
        return analyzeResult(trace);
    }

    public TestResult testServerKeyExchangeSignature(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the client is verifying the signature in the SKE message");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        WorkflowTrace trace = createIncorrectSkeSignatureTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_SERVER_KEY_EXCHANGE_SIGNATURE");
        return analyzeResult(trace);
    }

    public TestResult testServerKeyExchangeEmptySignature(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the client is verifying the signature in the SKE message if the signature is new byte[0]");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        WorkflowTrace trace = createEmptySkeSignatureTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_SERVER_KEY_EXCHANGE_EMPTY_SIGNATURE");
        return analyzeResult(trace);
    }

    public TestResult testServerKeyExchangeWithoutSignature(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the client is allowing SKE messages without a signature at all (including length field");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        WorkflowTrace trace = createMissingSkeSignatureTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_SERVER_KEY_EXCHANGE_WITHOUT_SIGNATURE");
        return analyzeResult(trace);
    }

    private TestResult analyzeResult(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. SKE was accepted."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable."
                            + AnsiColor.RESET);
            return TestResults.FALSE;
        } else {
            LOGGER.debug("Trace did not execute as planned. Signature is likely verified.");
            return extractProofResult(trace);
        }
    }

    /**
     * Creates a trace that sends a CertificateVerify message with an invalid signature. The public
     * key in the CKE message will be our value.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<----SH Flight----|    Forward    |<---SH Flight-----|
     * |-------CCS------->| BuffRecv Till
     *                    |->Copy Buff.-> |
     *                      Pop and Send  |---Certificate--->|
     *                      Dynamic Send  |-------CKE------->|
     *                           POP      |                         //Original CKE
     *                      Pop and Send  |-------CV-------->|      //Signature is invalid now
     *                          Send      |-------CCS,FIN--->|
     *                      Receive Till  |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createInvalidSignatureCvTrace(
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
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, true, true));

        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Cert
        trace.addTlsAction(
                new SendDynamicClientKeyExchangeAction(
                        ATTACKER_TO_SERVER_CONNECTION)); // This invalidates the CV
        // message we are going to send
        trace.addTlsAction(
                new PopBufferedMessageAction(ATTACKER_TO_SERVER_CONNECTION)); // Delete original CKE
        trace.addTlsAction(new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Send original CV
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
     * Creates a trace that
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<----SH Flight----|    Forward    |<---SH Flight-----|
     * |-------CCS------->| BuffRecv Till
     *                    |->Copy Buff.-> |
     *                      Pop and Send  |---Certificate--->|
     *                      Dynamic Send  |-------CKE------->|
     *                          Send      |-------CV[0]----->|
     *                          Send      |-------CCS,FIN--->|
     *                      Receive Till  |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createEmptyCvTrace(WebRtcPlatformReport report, Config config) {
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
                new BufferedReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Sends Certificate message
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage();
        certificateVerify.setSignature(Modifiable.explicit(new byte[0]));
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
     * |<----SH Flight----|    Forward    |<---SH Flight-----|
     * |-------CCS------->| BuffRecv Till
     *                    |->Copy Buff.-> |
     *                      Pop and Send  |---Certificate--->|
     *                      Dynamic Send  |-------CKE------->|
     *                          Send      |-------CV[0]*---->| // Malformed CV message
     *                          Send      |-------CCS,FIN--->|
     *                      Receive Till  |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createMissingSignatureCvTrace(
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
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, true, true));

        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(ATTACKER_TO_SERVER_CONNECTION)); // Sends Certificate message
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage();
        certificateVerify.setSignature(Modifiable.explicit(new byte[0]));
        certificateVerify.setLength(Modifiable.sub(2));
        certificateVerify.setCompleteResultingMessage(Modifiable.delete(-1, 2));
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
     * Creates a trace that sends an SKE message to the client with an invalid signature
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                      BuffRecv. Till|<--------SHD------|
     *                    |<-----Copy----<|
     * |<----ServerHello--|    Pop Send
     * |<----Certificate--|    Pop Send
     * |<---SKE*,CR,SHD---|      Send                          //SKE message with invalid signature
     * |---Certificate--->|  Receive Till                      //If we receive a certificate our trace is accepted
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createIncorrectSkeSignatureTrace(
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

        // receive SH and Certificate, forward them to the client
        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends ServerHello
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends Certificate

        ServerKeyExchangeMessage serverKeyExchangeMessage = createServerKeyExchangeMessage(report);
        serverKeyExchangeMessage.setSignature(
                Modifiable.xor(
                        new byte[] {(byte) 0xFF, (byte) 0xFF},
                        10)); // Flip some bits in the middle of the signature, signature is invalid
        // anyways
        trace.addTlsAction(new SendAction(CLIENT_TO_ATTACKER_CONNECTION, serverKeyExchangeMessage));
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Pop original ske
        if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE) == TestResults.TRUE) {
            trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends CR
        }
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends SHD

        trace.addTlsAction(
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    /**
     * Creates a trace that sends an SKE message to the client with an empty signature
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                      BuffRecv. Till|<--------SHD------|
     *                    |<-----Copy----<|
     * |<----ServerHello--|    Pop Send
     * |<----Certificate--|    Pop Send
     * |<---SKE[0],CR,SHD-|      Send                          //SKE message with an empty signature
     * |---Certificate--->|  Receive Till                      //If we receive a certificate our trace is accepted
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createEmptySkeSignatureTrace(WebRtcPlatformReport report, Config config) {
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

        // receive SH and Certificate, forward them to the client
        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends ServerHello
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends Certificate

        ServerKeyExchangeMessage serverKeyExchangeMessage = createServerKeyExchangeMessage(report);
        serverKeyExchangeMessage.setSignature(Modifiable.explicit(new byte[0]));

        trace.addTlsAction(new SendAction(CLIENT_TO_ATTACKER_CONNECTION, serverKeyExchangeMessage));
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Pop original ske
        if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE) == TestResults.TRUE) {
            trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends CR
        }
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends SHD
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new CertificateMessage()));
        return trace;
    }

    /**
     * Creates a trace that sends a malformed SKE message to the client without a signature and
     * signature length field
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                      BuffRecv. Till|<--------SHD------|
     *                    |<-----Copy----<|
     * |<----ServerHello--|    Pop Send
     * |<----Certificate--|    Pop Send
     * |<--SKE[0]*,CR,SHD-|      Send                          //SKE message without signature or signature length field
     * |---Certificate--->|  Receive Till                      //If we receive a certificate our trace is accepted
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createMissingSkeSignatureTrace(
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

        // receive SH and Certificate, forward them to the client
        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends ServerHello
        trace.addTlsAction(
                new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends Certificate

        ServerKeyExchangeMessage serverKeyExchangeMessage = createServerKeyExchangeMessage(report);
        serverKeyExchangeMessage.setSignature(Modifiable.explicit(new byte[0]));
        // this works ¯\_(ツ)_/¯
        serverKeyExchangeMessage.setCompleteResultingMessage(Modifiable.delete(-1, 2));
        serverKeyExchangeMessage.setLength(Modifiable.sub(2));

        trace.addTlsAction(new SendAction(CLIENT_TO_ATTACKER_CONNECTION, serverKeyExchangeMessage));
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Pop original ske
        if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE) == TestResults.TRUE) {
            trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends CR
        }
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Sends SHD

        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new CertificateMessage()));
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

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(WebRtcProperties.COMPLETELY_FUNCTIONAL);
    }
}
