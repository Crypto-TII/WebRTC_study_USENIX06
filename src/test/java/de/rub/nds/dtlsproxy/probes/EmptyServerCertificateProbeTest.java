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

import de.rub.nds.dtlsproxy.config.ConnectionConfig;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.dtls.EmptyServerCertificateProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class EmptyServerCertificateProbeTest extends ProbingTest {

    /**
     * Tests wether a client always proceeding is acknowledged by probe
     *
     * @throws IOException
     */
    @Test
    public void testProceedingViaFullHandshake() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(SimulationLibrary.FULL_HS_CLIENT_SIDE));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        EmptyServerCertificateProbe probe = new EmptyServerCertificateProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                TestResults.FALSE, report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_CERT));
    }

    /**
     * Tests wether a client never proceeding and sending alert is acknowledged by probe
     *
     * @throws IOException
     */
    @Test
    public void testNoticingViaAlert() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS_CLIENT_SIDE;
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_CKEX);
        actions.add(SimulatedAction.alertBadCert(600, ConnectionSide.CLIENT));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        EmptyServerCertificateProbe probe = new EmptyServerCertificateProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_CERT).toString());
    }

    /**
     * Tests wether a client never proceeding and abandoning the connection is acknowledged by probe
     *
     * @throws IOException
     */
    @Test
    public void testNoticingViaAbort() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS_CLIENT_SIDE;
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_CKEX);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        EmptyServerCertificateProbe probe = new EmptyServerCertificateProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_CERT).toString());
    }
}
