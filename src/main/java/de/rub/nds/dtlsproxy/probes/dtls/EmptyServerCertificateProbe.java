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
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EmptyServerCertificateProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public EmptyServerCertificateProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.CLIENT_NOTICES_EMPTY_CERT,
                executeWithRetries(() -> clientTestEmptyCertificate(report)));
    }

    private TestResult clientTestEmptyCertificate(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the server is accepting an empty certificate message");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createTestEmptyCertificateWorkflowTrace(report, config);

        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_EMPTY_CERTIFICATE_CLIENT");

        return analyzeResult(trace);
    }

    private TestResult analyzeResult(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            LOGGER.info(
                    "Trace executed as planned. Handshake completed successfully."
                            + AnsiColor.RED
                            + AnsiColor.BOLD
                            + " Server send CCS,FIN and is vulnerable."
                            + AnsiColor.RESET);
            return TestResults.FALSE;
        } else {
            LOGGER.debug(
                    "Trace did not execute as planned. Server does not allow optional authentication.");
            return extractProofResult(trace);
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
     * |---ClientHello--->|    Receive
     * |<-Server Hello----|     Send
     * |<---EMPTY CERT----|     Send
     * |<-[SKE], CR, SHD--|     Send
     * |--------CCS------>|  Receive Till
     *
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createTestEmptyCertificateWorkflowTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        trace.addTlsAction(
                new ReceiveAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));
        CertificateMessage certificateMessage = new CertificateMessage();
        certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ServerHelloMessage(config),
                        certificateMessage));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(),
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
