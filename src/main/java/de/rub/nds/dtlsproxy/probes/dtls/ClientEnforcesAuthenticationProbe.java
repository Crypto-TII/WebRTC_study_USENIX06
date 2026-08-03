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
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientEnforcesAuthenticationProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientEnforcesAuthenticationProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.CLIENT_ENFORCES_CLIENT_AUTHENTICATION,
                executeWithRetries(() -> getClientVerifiesCertificateResult(report)));
    }

    private TestResult getClientVerifiesCertificateResult(WebRtcPlatformReport report) {
        LOGGER.info("Testing if the client is enforcing that the server asks for authentication");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createNonCertificateRequestTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_ENFORCES_CLIENT_AUTHENTICATION");
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
                    "Trace did not execute as planned. Likely that the client enforced authentication.");
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
     * |---ClientHello--->|   Forward
     *                         Buffer      |<-SH,C,SKE*,CR,SHD|
     *                    |<-Copy Buffers<-|
     * |<--------SH-------|     Pop
     * |<--------C--------|     Pop
     * |<--------SKE------|     Pop*
     *                (CR*,SHD remains in buffer)
     * |<--------SHD------|     Send
     * |ChangeCipherSpec->| Receive Till
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client verifies the certificate
     */
    private WorkflowTrace createNonCertificateRequestTrace(
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
                new BufferedReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new CopyBuffersAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // ServerHello
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Certificate
        if (report.getDefaultSelectedCipherSuite().isEphemeral()) {
            trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // SKE
        }
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloDoneMessage()));
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
