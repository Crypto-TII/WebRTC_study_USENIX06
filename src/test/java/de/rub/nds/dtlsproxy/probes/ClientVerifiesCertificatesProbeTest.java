/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

import de.rub.nds.dtlsproxy.config.ConnectionConfig;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.dtls.ClientVerifiesCertificatesProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.utils.PacketLibrary;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClientVerifiesCertificatesProbeTest extends ProbingTest {

    /**
     * Tests wether missing verification is detected
     *
     * @throws IOException
     */
    @Test
    void testNotVerifyingViaFullHandshake() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(SimulationLibrary.FULL_HS_CLIENT_SIDE));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ClientVerifiesCertificatesProbe probe =
                new ClientVerifiesCertificatesProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                new DetailedResult<String>(TestResults.FALSE, "Finished handshake"),
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE));
    }

    /**
     * Tests wether present verification is detected when the handshake is abandoned by the client
     *
     * @throws IOException
     */
    @Test
    void testVerifyingViaAbort() throws IOException {

        List<SimulatedAction> actions = new ArrayList<>();
        actions.add(
                new SimulatedAction(0, ConnectionSide.CLIENT, PacketLibrary.CLIENT_HELLO_1, "ch"));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        ProxyConfiguration proxyConfiguration = new ProxyConfiguration();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        proxyConfiguration,
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        ClientVerifiesCertificatesProbe probe =
                new ClientVerifiesCertificatesProbe(webrtcExecutionContext);
        runWithRecordReorderingDisabled(proxyConfiguration, report, probe);

        assertEquals(
                new DetailedResult<String>(
                        TestResults.TRUE,
                        "Received no alert. No proof. Last message: <no response>"),
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE));
    }

    /**
     * Tests wether present verification is detected when alert is send from client
     *
     * @throws IOException
     */
    @Test
    void testVerifyingViaAlert() throws IOException {

        List<SimulatedAction> actions = new ArrayList<>();
        actions.add(
                new SimulatedAction(0, ConnectionSide.CLIENT, PacketLibrary.CLIENT_HELLO_1, "ch"));
        actions.add(SimulatedAction.alertBadCert(700, ConnectionSide.CLIENT));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        ProxyConfiguration proxyConfiguration = new ProxyConfiguration();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        proxyConfiguration,
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        ClientVerifiesCertificatesProbe probe =
                new ClientVerifiesCertificatesProbe(webrtcExecutionContext);
        runWithRecordReorderingDisabled(proxyConfiguration, report, probe);

        assertEquals(
                new DetailedResult<String>(
                        TestResults.TRUE, "Received alert message: Alert(FATAL,BAD_CERTIFICATE)"),
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE));
    }

    private void runWithRecordReorderingDisabled(
            ProxyConfiguration proxyConfiguration,
            WebRtcPlatformReport report,
            ClientVerifiesCertificatesProbe probe) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        proxyConfiguration,
                        report,
                        ClientVerifiesCertificatesProbe.CLIENT_TO_ATTACKER_CONNECTION,
                        ClientVerifiesCertificatesProbe.ATTACKER_TO_SERVER_CONNECTION);
        config.setReorderReceivedDtlsRecords(false);

        try (MockedStatic<TraceUtil> traceUtilMock =
                mockStatic(TraceUtil.class, CALLS_REAL_METHODS)) {
            traceUtilMock
                    .when(
                            () ->
                                    TraceUtil.getFunctionalConfig(
                                            proxyConfiguration,
                                            report,
                                            ClientVerifiesCertificatesProbe
                                                    .CLIENT_TO_ATTACKER_CONNECTION,
                                            ClientVerifiesCertificatesProbe
                                                    .ATTACKER_TO_SERVER_CONNECTION))
                    .thenReturn(config);
            probe.test(report);
        }
    }
}
