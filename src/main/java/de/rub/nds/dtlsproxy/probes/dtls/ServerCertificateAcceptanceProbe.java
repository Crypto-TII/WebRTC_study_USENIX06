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
import de.rub.nds.dtlsproxy.action.ForwardServerFlightAction;
import de.rub.nds.dtlsproxy.enums.AnsiColor;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
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
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.util.MimicryEngine;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Tests if the server is accepting a certificates that are not valid. */
public class ServerCertificateAcceptanceProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerCertificateAcceptanceProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.SERVER_REJECTS_MIMICRY_CERTIFICATE,
                executeWithRetries(() -> getServerRejectsMimicryCertificate(report)));
        report.putResult(
                WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL,
                executeWithRetries(() -> getServerRejectsDoubleLeafTrick(report, false)));
        report.putResult(
                WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER,
                executeWithRetries(() -> getServerRejectsDoubleLeafTrick(report, true)));
        report.putResult(
                WebRtcProperties.SERVER_REJECTS_CORRUPTED_CERTIFICATE,
                executeWithRetries(() -> getServerRejectsCorruptedCertificate(report)));
    }

    private TestResult getServerRejectsCorruptedCertificate(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing if the server is rejecting corrupted certificates (missing signature) certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);

        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleClientCertificateChain =
                report.getExampleClientCertificateChain();
        for (int i = 0; i < exampleClientCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleClientCertificateChain);

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
        execute(connection, "SERVER_REJECT_CORRUPTED_CERTIFICATE_MISSING_SIGNATURE");
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            LOGGER.debug("Trace did not execute as planned.");
            return extractProofResult(trace);
        }
    }

    private TestResult getServerRejectsDoubleLeafTrick(
            WebRtcPlatformReport report, boolean realChainFirst) {
        LOGGER.info("Testing if the server is rejecting double leaf certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);

        WorkflowTrace trace =
                createCertificateDoubleCertificateTrace(report, config, realChainFirst);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_REJECTS_DOUBLE_CERT_TRICK_RF_" + realChainFirst);
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            LOGGER.debug("Trace did not execute as planned.");
            return extractProofResult(trace);
        }
    }

    private TestResult getServerRejectsMimicryCertificate(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server is rejecting mimicry certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        // set an explicit signature and hash algorithm to use so we do not run into a mismatch in
        // algorithms
        // between the observed (mimiced) certificated and the TLS Attacker selected one
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);

        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleClientCertificateChain =
                report.getExampleClientCertificateChain();
        for (int i = 0; i < exampleClientCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleClientCertificateChain);
        config.setDefaultExplicitCertificateChain(mimicryCertificateChain);
        config.setCertificateChainConfig(certificateConfigs);

        /* We do not filter client cipher suites here as the server will support some cipher suite
        from the default offered client cipher suites we have seen.
        Additionally, we required that the server offers us the signature algorithm,
        which is used in the default used client certificate.
        It does not make sense to filter cipher suites here to achieve this goal because the server offered signature
        and hash algorithms do not depend on the selection of client cipher suites offered.
        Therefore, we choose to offer the same selection of cipher suites as when the exampleClientCertificateChain
        was recorded no to alter the server behaviour here. */
        config.setDefaultClientSupportedCipherSuites(report.getClientSupportedCipherSuites());

        WorkflowTrace trace = createCertificateAcceptanceTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_REJECTS_MIMICRY_CERTIFICATE");
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so we went undetected
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
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
     * |---ClientHello--->|     Forward   |---ClientHello--->|
     *                    |  Receive Till |<-----SHD---------|
     *                    |      Send     |C,CKE,CV,CCS,FIN->|
     *                    |  Receive Till |<-ChangeCipherSpec|
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
                new ForwardMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ClientHelloMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendAction(ATTACKER_TO_SERVER_CONNECTION, new CertificateMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new FinishedMessage()));
        return trace;
    }

    /**
     * Create a trace that will sends a different Certificate than expected.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|     Forward   |---ClientHello--->|
     * |<-SH,C*,SKE,CR,SHD| Forward Flight|<-SH,C*,SKE,CR,SHD|
     * |----Certificate-->|   Inject Cert |--Certificate*--->|
     *                    |      Send     |--CKE,CV,CCS,FIN-->
     *                    |  Receive Till |<-ChangeCipherSpec|
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client verifies the certificate
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
                new ForwardServerFlightAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, true, false));
        // the original one
        trace.addTlsAction(
                new DynamicCertificateInjectionAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        injectRealFirst,
                        false));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
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
