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
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StaticCertificateProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public StaticCertificateProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        TestResult staticCerts = executeWithRetries(() -> checkStaticCerts(report));
        if (staticCerts instanceof DoubleResult) {
            report.putResult(
                    WebRtcProperties.STATIC_SERVER_CERTIFICATE,
                    ((DoubleResult) staticCerts).getFirstResult());
            report.putResult(
                    WebRtcProperties.STATIC_CLIENT_CERTIFICATE,
                    ((DoubleResult) staticCerts).getSecondResult());
        } else {
            // Test failure due to repeated errors in trace execution
            report.putResult(
                    WebRtcProperties.STATIC_SERVER_CERTIFICATE, TestResults.ERROR_DURING_TEST);
            report.putResult(
                    WebRtcProperties.STATIC_CLIENT_CERTIFICATE, TestResults.ERROR_DURING_TEST);
        }
    }

    public DoubleResult checkStaticCerts(WebRtcPlatformReport report) {
        TestResult staticServerCertificate;
        TestResult staticClientCertificate;

        LOGGER.info("Testing if Server/Client are reusing certificates");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        WorkflowTrace firstTrace = createExtractCertificateTrace(report, config);
        TraceableConnection firstConnection = createConnection(config, firstTrace);
        execute(firstConnection, "TESTING_STATIC_CERTIFICATE_FIRST_TIME");

        WorkflowTrace secondTrace = createExtractCertificateTrace(report, config);

        TraceableConnection secondConnection = createConnection(config, secondTrace);
        execute(secondConnection, "TESTING_STATIC_CERTIFICATE_SECOND_TIME");

        if (firstTrace.executedAsPlanned() && secondTrace.executedAsPlanned()) {
            if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE)
                    == TestResults.TRUE) {
                if (clientCertificatesAreEqual(
                        firstConnection.getState(), secondConnection.getState())) {
                    staticClientCertificate = TestResults.TRUE;
                } else {
                    staticClientCertificate = TestResults.FALSE;
                }
            } else {
                LOGGER.debug("Server did not request a certificate");
                staticClientCertificate = TestResults.CANNOT_BE_TESTED;
            }
            if (serverCertificatesAreEqual(
                    firstConnection.getState(), secondConnection.getState())) {
                staticServerCertificate = TestResults.TRUE;
            } else {
                staticServerCertificate = TestResults.FALSE;
            }
        } else {
            throw new RuntimeException(
                    "Not all actions executed in either trace: "
                            + firstTrace.toString()
                            + "\n"
                            + secondTrace.toString());
        }

        return new DoubleResult(staticServerCertificate, staticClientCertificate);
    }

    private class DoubleResult implements TestResult {
        private TestResult firstResult;
        private TestResult secondResult;

        public DoubleResult(TestResult firstResult, TestResult secondResult) {
            this.firstResult = firstResult;
            this.secondResult = secondResult;
        }

        public TestResult getFirstResult() {
            return firstResult;
        }

        public TestResult getSecondResult() {
            return secondResult;
        }

        @Override
        public String getName() {
            return firstResult.getName() + " and " + secondResult.getName();
        }
    }

    /**
     * Create a trace that tries to extract the certificate of both connection. On the client side
     * we wait for the ccs message to avoid
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<---SH Flight-----|    Forward    |<---SH Flight-----|
     * |-------CCS------->|  Receive Till
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test if the client verifies the certificate
     */
    private WorkflowTrace createExtractCertificateTrace(
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
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    private boolean serverCertificatesAreEqual(State state, State state2) {
        X509CertificateChain serverCertificate =
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getServerCertificateChain();
        X509CertificateChain serverCertificate2 =
                state2.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getServerCertificateChain();
        return Objects.equals(serverCertificate, serverCertificate2)
                && serverCertificate != null
                && serverCertificate.getCertificateList().size() > 0;
    }

    private boolean clientCertificatesAreEqual(State state, State state2) {
        X509CertificateChain clientCertificate =
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getClientCertificateChain();
        X509CertificateChain clientCertificate2 =
                state2.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getClientCertificateChain();
        return Objects.equals(clientCertificate, clientCertificate2)
                && clientCertificate != null
                && clientCertificate.getCertificateList().size() > 0;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(WebRtcProperties.COMPLETELY_FUNCTIONAL);
    }
}
