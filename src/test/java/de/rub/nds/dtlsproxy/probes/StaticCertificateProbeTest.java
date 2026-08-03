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
import de.rub.nds.dtlsproxy.probes.dtls.StaticCertificateProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.utils.PacketLibrary;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class StaticCertificateProbeTest extends ProbingTest {

    /**
     * Tests if non static client and static server cert are recognised
     *
     * @throws IOException
     */
    @Test
    public void testClientNonStatic() throws IOException {

        List<SimulatedAction> simNonStatic0 = new ArrayList<>();
        simNonStatic0.add(
                new SimulatedAction(0, ConnectionSide.CLIENT, PacketLibrary.CLIENT_HELLO_5, "ch"));
        simNonStatic0.add(
                new SimulatedAction(
                        1,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS_3,
                        "sh"));
        simNonStatic0.add(
                new SimulatedAction(
                        2,
                        ConnectionSide.SERVER,
                        PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_3,
                        "sh c"));
        simNonStatic0.add(
                new SimulatedAction(
                        3,
                        ConnectionSide.CLIENT,
                        PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_6,
                        "ckex"));
        simNonStatic0.add(
                new SimulatedAction(
                        4,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_SESSION_TICKET_CCS_5,
                        "ccs"));
        simNonStatic0.add(
                new SimulatedAction(
                        5, ConnectionSide.CLIENT, PacketLibrary.CLIENT_ENC_ALERT_5, "alert"));

        List<SimulatedAction> simNonStatic1 = new ArrayList<>();
        simNonStatic1.add(
                new SimulatedAction(0, ConnectionSide.CLIENT, PacketLibrary.CLIENT_HELLO_5, "ch"));
        simNonStatic1.add(
                new SimulatedAction(
                        1,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS_3,
                        "sh"));
        simNonStatic1.add(
                new SimulatedAction(
                        2,
                        ConnectionSide.SERVER,
                        PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_3,
                        "sh c"));
        simNonStatic1.add(
                new SimulatedAction(
                        3,
                        ConnectionSide.CLIENT,
                        PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_7,
                        "ckex"));
        simNonStatic1.add(
                new SimulatedAction(
                        4,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_SESSION_TICKET_CCS_5,
                        "ccs"));
        simNonStatic1.add(
                new SimulatedAction(
                        5, ConnectionSide.CLIENT, PacketLibrary.CLIENT_ENC_ALERT_5, "alert"));

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.continuous(new List[] {simNonStatic0, simNonStatic1}));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.CLIENT_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.SERVER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, TestResults.TRUE);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        ProxyConfiguration proxyConfiguration = new ProxyConfiguration();
        Config config =
                TraceUtil.getFunctionalConfig(
                        proxyConfiguration,
                        report,
                        StaticCertificateProbe.CLIENT_TO_ATTACKER_CONNECTION,
                        StaticCertificateProbe.ATTACKER_TO_SERVER_CONNECTION);
        config.setReorderReceivedDtlsRecords(false);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        proxyConfiguration,
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        StaticCertificateProbe probe = new StaticCertificateProbe(webrtcExecutionContext);
        // replace config for this test as t he test data skips sequence numbers. TODO make this
        // more elegant. Config setter?
        try (MockedStatic<TraceUtil> traceUtilMock =
                mockStatic(TraceUtil.class, CALLS_REAL_METHODS)) {
            traceUtilMock
                    .when(
                            () ->
                                    TraceUtil.getFunctionalConfig(
                                            proxyConfiguration,
                                            report,
                                            StaticCertificateProbe.CLIENT_TO_ATTACKER_CONNECTION,
                                            StaticCertificateProbe.ATTACKER_TO_SERVER_CONNECTION))
                    .thenReturn(config);
            probe.test(report);
        }

        assertEquals(
                TestResults.FALSE, report.getResult(WebRtcProperties.STATIC_CLIENT_CERTIFICATE));
        assertEquals(
                TestResults.TRUE, report.getResult(WebRtcProperties.STATIC_SERVER_CERTIFICATE));
    }

    /**
     * Tests if static client and static server cert are recognised
     *
     * @throws IOException
     */
    @Test
    public void testClientStatic() throws IOException {

        List<SimulatedAction> actions =
                SimulationLibrary.remove(
                        SimulationLibrary.FULL_HS,
                        SimulationLibrary.INDEX_ID_SCCS,
                        SimulationLibrary.INDEX_ID_CA);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.CLIENT_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.SERVER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, TestResults.TRUE);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        StaticCertificateProbe probe = new StaticCertificateProbe(webrtcExecutionContext);
        probe.test(report);
        assertEquals(
                TestResults.TRUE, report.getResult(WebRtcProperties.STATIC_CLIENT_CERTIFICATE));
        assertEquals(
                TestResults.TRUE, report.getResult(WebRtcProperties.STATIC_SERVER_CERTIFICATE));
    }
}
