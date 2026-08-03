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
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerVerifiesCertificatesProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerVerifiesCertificatesProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.SERVER_VERIFIES_CERTIFICATE,
                executeWithRetries(() -> testServerVerifiesCertificate(report)));
        if ((getProxyConfiguration().getExternalCertificates() == null
                        && getProxyConfiguration().getExternalKeys() != null)
                || (getProxyConfiguration().getExternalCertificates() != null
                        && getProxyConfiguration().getExternalKeys() == null)) {
            LOGGER.warn(
                    "External certificate and key must be provided together. Cannot test like this");
        } else if (getProxyConfiguration().getExternalCertificates() != null
                && getProxyConfiguration().getExternalCertificates().length > 0
                && getProxyConfiguration().getExternalKeys() != null
                && getProxyConfiguration().getExternalKeys().length > 0) {
            report.putResult(
                    WebRtcProperties.SERVER_REJECTS_PROVIDED_CERTIFICATE,
                    executeWithRetries(() -> testServerVerifiesCertificateExternal(report)));
        }
    }

    private TestResult testServerVerifiesCertificateExternal(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server is rejecting the externally provided certificates");

        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        X509Util.applyTrustedCertificate(report, config, getProxyConfiguration(), true);

        WorkflowTrace trace = createModifiedCertificateAcceptedTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_REJECTS_PROVIDED_CERTIFICATE");

        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace);
        } else if (trace.executedAsPlanned()) {
            // Handshake finished
            LOGGER.info(
                    "Trace executed as planned. Server accepted externally provided certificate."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " server send CCS,FIN and is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            return extractProofResult(trace);
        }
    }

    public TestResult testServerVerifiesCertificate(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server is verifying the certificates it receives");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        // adjust the TLS attacker cert to fit previously supported algorithms
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);

        WorkflowTrace trace = createModifiedCertificateAcceptedTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_VERIFIES_CERTIFICATE");

        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace);
        } else if (trace.executedAsPlanned()) {
            // Handshake finished
            LOGGER.info(
                    "Trace executed as planned. Server does not very certificate."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " server send CCS,FIN and is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            return extractProofResult(trace);
        }
    }

    /**
     * Creates a trace that sends a Certificate message with a modified certificate chain.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                       Receive Till |<------SHD--------|
     *                           Send     |---Certificate--->|
     *                       Dynamic Send |-------CKE------->|
     *                           Send     |----CV,CCS,FIN--->|
     *                       Receive Till |<------CCS--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createModifiedCertificateAcceptedTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        // Not using a forward action so TLS Attacker would explicitly build the CH again with
        // ciphers from our config
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));
        trace.addTlsAction(
                new SendAction(ATTACKER_TO_SERVER_CONNECTION, new ClientHelloMessage(config)));
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
