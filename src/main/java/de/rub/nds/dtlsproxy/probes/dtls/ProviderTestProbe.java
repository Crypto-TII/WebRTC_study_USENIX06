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
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Test that checks wether a connection can be successfully be attempted f.e. if the booter is
 * functional
 */
public class ProviderTestProbe extends DtlsProbe {

    private static final int REEXECUTION_COUNTER = 3;

    private static final Logger LOGGER = LogManager.getLogger();

    public ProviderTestProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {

        try {
            LOGGER.info("Starting ProviderTestProbe");
            int inboundWasDtlsClient = 0;
            for (int i = 0; i < REEXECUTION_COUNTER; i++) {
                ConnectionInterface abstractConnection = getConnectionProvider().createConnection();
                if (abstractConnection.isInboundTheDtlsClient()) {
                    inboundWasDtlsClient++;
                }
                getConnectionProvider().release(abstractConnection, true);
            }
            if (inboundWasDtlsClient == 0) {
                report.putResult(WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, false);
                if (getProxyConfiguration().isOnlyTestLocal()) {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.FALSE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
                } else if (getProxyConfiguration().isOnlyTestRemote()) {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.FALSE);
                } else {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
                }
            } else if (inboundWasDtlsClient == REEXECUTION_COUNTER) {
                report.putResult(WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, true);
                if (getProxyConfiguration().isOnlyTestLocal()) {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.FALSE);
                } else if (getProxyConfiguration().isOnlyTestRemote()) {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.FALSE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
                } else {
                    report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                    report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
                }
            } else {
                report.putResult(
                        WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION, TestResults.PARTIALLY);

                report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
                report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
            }
            report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, true);
            LOGGER.trace("Provider checks out");
        } catch (RuntimeException e) {
            LOGGER.warn("An exception occured", e);
            LOGGER.warn("Determined {} provider to be non functional!", report.getTargetName());
            report.putResult(
                    WebRtcProperties.PROVIDER_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, e.getMessage()));
            report.putResult(
                    WebRtcProperties.COMPLETELY_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, e.getMessage()));
        }
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return new LinkedList<>(List.of(WebRtcProperties.COMPLETELY_FUNCTIONAL));
    }
}
