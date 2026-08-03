/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.dtlsproxy.action.DynamicCertificateInjectionAction;
import de.rub.nds.dtlsproxy.enums.AnsiColor;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.CryptoUtil;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.util.MimicryEngine;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Tests if the client is accepting a certificates that are not valid. */
public class ClientCertificateAcceptanceProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientCertificateAcceptanceProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.CLIENT_REJECTS_MIMICRY_CERTIFICATE,
                executeWithRetries(() -> getClientRejectsMimicryCertificate(report)));
        report.putResult(
                WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL,
                executeWithRetries(() -> getClientRejectsDoubleLeafTrick(report, false)));
        report.putResult(
                WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER,
                executeWithRetries(() -> getClientRejectsDoubleLeafTrick(report, true)));
        report.putResult(
                WebRtcProperties.CLIENT_REJECTS_CORRUPTED_CERTIFICATE,
                executeWithRetries(() -> getClientRejectsCorruptedCertificate(report)));
    }

    private TestResult getClientRejectsCorruptedCertificate(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the client is rejecting corrputed certificates (missing signature) certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        // set an explicit signature and hash algorithm to use so we do not run into a mismatch in
        // algorithms between the observed (mimiced) certificated and the TLS Attacker selected one
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleServerCertificateChain =
                report.getExampleServerCertificateChain();
        for (int i = 0; i < exampleServerCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleServerCertificateChain);

        // make sure we select a cipher suite fitting to the mimiced cert
        CryptoUtil.adjustServerCiphers(
                config, exampleServerCertificateChain.getLeaf().getCertificateKeyType());

        mimicryCertificateChain
                .getCertificate(0)
                .getSignature()
                .getContent()
                .addModification(new ByteArrayExplicitValueModification(new byte[0]));
        mimicryCertificateChain
                .getCertificate(0)
                .getSignature()
                .getTagOctets()
                .addModification(new ByteArrayExplicitValueModification(new byte[0]));
        mimicryCertificateChain
                .getCertificate(0)
                .getSignature()
                .getLengthOctets()
                .addModification(new ByteArrayExplicitValueModification(new byte[0]));

        Asn1PreparatorHelper.prepareAfterContent(
                mimicryCertificateChain.getCertificate(0).getSignature());
        X509CertificatePreparator preparator =
                (X509CertificatePreparator)
                        mimicryCertificateChain.getCertificate(0).getPreparator(null);
        mimicryCertificateChain.getCertificate(0).setContent(preparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(mimicryCertificateChain.getCertificate(0));

        config.setDefaultExplicitCertificateChain(mimicryCertificateChain);
        config.setCertificateChainConfig(certificateConfigs);
        WorkflowTrace trace = createCertificateAcceptanceTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_REJECT_CORRUPTED_CERTIFICATE_MISSING_SIGNATURE");
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            LOGGER.debug("Trace did not execute as planned.");
            return extractProofResult(trace);
        }
    }

    private TestResult getClientRejectsDoubleLeafTrick(
            WebRtcPlatformReport report, boolean realChainFirst) {
        LOGGER.info("Testing if the client is rejecting double leaf trick certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleServerCertificateChain =
                report.getExampleServerCertificateChain();
        for (int i = 0; i < exampleServerCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleServerCertificateChain);
        config.setDefaultExplicitCertificateChain(mimicryCertificateChain);
        config.setCertificateChainConfig(certificateConfigs);
        CryptoUtil.adjustServerCiphers(
                config, exampleServerCertificateChain.getLeaf().getCertificateKeyType());
        WorkflowTrace trace =
                createCertificateDoubleCertificateTrace(report, config, realChainFirst);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_REJECTS_DOUBLE_CERT_TRICK_RF_" + realChainFirst);
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            LOGGER.debug("Trace did not execute as planned.");
            return extractProofResult(trace);
        }
    }

    private TestResult getClientRejectsMimicryCertificate(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the client is rejecting mimicry certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleServerCertificateChain =
                report.getExampleServerCertificateChain();
        for (int i = 0; i < exampleServerCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleServerCertificateChain);
        config.setDefaultExplicitCertificateChain(mimicryCertificateChain);
        config.setCertificateChainConfig(certificateConfigs);
        CryptoUtil.adjustServerCiphers(
                config, exampleServerCertificateChain.getLeaf().getCertificateKeyType());
        WorkflowTrace trace = createCertificateAcceptanceTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_REJECTS_MIMICRY_CERTIFICATE");
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            if (connection
                            .getState()
                            .getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                            .getSelectedCipherSuite()
                            .isEphemeral()
                    && WorkflowTraceResultUtil.didReceiveMessage(
                            trace, ProtocolMessageType.CHANGE_CIPHER_SPEC)) {
                LOGGER.debug("Received a CCS but not Finished? Looks like vulnerability");
                return new DetailedResult<String>(
                        TestResults.FALSE, "Received CCS but not Finished. Investigate!");
            }
            LOGGER.debug("Trace did not execute as planned.");
            return extractProofResult(trace);
        }
    }

    /**
     * Create a trace that will sends a different Certificate than expected.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Receive
     * |<---ServerHello---|     Send
     * |<---Certificate---|     Send
     * |<--------SKE------|     Send
     * |<---CertRequest---|     Send
     * |<-ServerHelloDone-|     Send
     * |ChangeCipherSpec->| Receive Till
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client verifies the certificate
     */
    private WorkflowTrace createCertificateAcceptanceTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        trace.addTlsAction(
                new ReceiveAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloMessage(config)));
        trace.addTlsAction(new SendDynamicServerCertificateAction(CLIENT_TO_ATTACKER_CONNECTION));
        // the original one
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    /**
     * Create a trace that will sends a different Certificate than expected.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward     |--->ClientHello->|
     * |<---ServerHello---|  ForwardTill   |<---ServerHello--|
     * |<----CERT**-------| DynamicInject  |<---CERT---------|
     * |<--------SKE------|  SendDynamic
     * |<---CertRequest---|     Send
     * |<-ServerHelloDone-|     Send
     * |----FINISHED----->| Receive Till
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client accepted the certificate/SKE
     */
    private WorkflowTrace createCertificateDoubleCertificateTrace(
            WebRtcPlatformReport report, Config config, boolean injectRealFirst) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        // set default cert chain to null for TLS-Attacker to use custom chain in CertificateMessage
        // instead
        config.setDefaultExplicitCertificateChain((List<CertificateBytes>) null);

        trace.addTlsAction(
                new ForwardMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ClientHelloMessage()));
        trace.addTlsAction(
                new TightForwardTillAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ServerHelloMessage()));
        trace.addTlsAction(
                new DynamicCertificateInjectionAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        injectRealFirst,
                        true));
        // the original one
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new FinishedMessage()));
        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.WANT_TO_TEST_CLIENT,
                WebRtcProperties.PROVIDER_FUNCTIONAL);
    }
}
