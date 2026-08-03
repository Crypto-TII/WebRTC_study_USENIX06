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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientVerifiesCertificatesProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientVerifiesCertificatesProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE,
                executeWithRetries(() -> getClientVerifiesCertificateResult(report)));
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
                    WebRtcProperties.CLIENT_REJECTS_PROVIDED_CERTIFICATE,
                    executeWithRetries(() -> testClientVerifiesCertificateExternal(report)));
        }
    }

    private TestResult testClientVerifiesCertificateExternal(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the client is rejecting the externally provided certificates");

        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        X509Util.applyTrustedCertificate(report, config, getProxyConfiguration(), false);

        WorkflowTrace trace = createModifiedCertificateAcceptedTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_REJECTS_PROVIDED_CERTIFICATE");

        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished
            LOGGER.info(
                    "Trace executed as planned. Client accepted externally provided certificate."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " client continued with handshake and is vulnerable."
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            return extractProofResult(trace);
        }
    }

    private TestResult getClientVerifiesCertificateResult(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the client is verifying the certificates it receives");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createModifiedCertificateAcceptedTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_VERIFIES_CERTIFICATE_FULL_HS");
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so there was no check
            LOGGER.info(
                    "Trace executed as planned."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Client is vulnerable"
                            + AnsiColor.RESET);
            return new DetailedResult<String>(TestResults.FALSE, "Finished handshake");
        } else {
            LOGGER.debug(
                    "Trace did not execute as planned. Likely that client verified the certificate.");
            return extractProofResult(trace);
        }
    }

    /**
     * Create a trace that will send a different Certificate than expected. Depending on the cipher
     * suite, the SKE message will also me adjusted.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->| Receive Till
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
    private WorkflowTrace createModifiedCertificateAcceptedTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloMessage(config)));
        trace.addTlsAction(
                new SendDynamicServerCertificateAction(
                        CLIENT_TO_ATTACKER_CONNECTION)); // TODO Create a certificate that mimics
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

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL, WebRtcProperties.WANT_TO_TEST_CLIENT);
    }
}
