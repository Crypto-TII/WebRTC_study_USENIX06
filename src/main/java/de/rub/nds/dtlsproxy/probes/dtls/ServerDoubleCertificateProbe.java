/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Checks wether the Server Certificate check can be bypassed by supplying the original client
 * certificate but additionally our own.
 */
public class ServerDoubleCertificateProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerDoubleCertificateProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        report.putResult(
                WebRtcProperties.SERVER_NOTICES_MISSING_CV,
                executeWithRetries(() -> testIfCertificateInjectable(report)));
    }

    public TestResult testIfCertificateInjectable(WebRtcPlatformReport report) {
        LOGGER.info("");
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);

        WorkflowTrace trace = createDoubleCertificateSendTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "TEST_DOUBLE_CERTIFICATE_INJECTION_TRICK");
        return analyzeResults(trace);
    }

    private TestResult analyzeResults(WorkflowTrace trace) {
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            return TestResults.FALSE;
        } else {
            return extractProofResult(trace);
        }
    }

    private WorkflowTrace createDoubleCertificateSendTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        /**
         * We cannot implement this right now. What we need to do is establish an attacker
         * connection at the same time we establish a client connection and then inject the client
         * certificate into our connection to see if the server accepts it AND treats us as the real
         * original client. We cannot do it the other way round as we do not have the cke private
         * key. A variant of this could be to inject our certificate into the client connection to
         * do a session fixation attack.
         */
        throw new UnsupportedOperationException();
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL,
                WebRtcProperties.SERVER_REQUESTS_CERTIFICATE);
    }
}
