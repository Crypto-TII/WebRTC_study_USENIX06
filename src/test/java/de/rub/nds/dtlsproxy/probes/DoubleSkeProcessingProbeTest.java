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
import de.rub.nds.dtlsproxy.probes.dtls.DoubleSkeProcessingProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class DoubleSkeProcessingProbeTest extends ProbingTest {

    /**
     * Tests whether abandoned handshake is correctly detected
     *
     * @throws IOException
     */
    @Test
    public void testVerifyingViaAbort() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions,
                        SimulationLibrary.INDEX_ID_SCCS,
                        SimulationLibrary.INDEX_ID_CKEX,
                        SimulationLibrary.INDEX_ID_CA);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        DoubleSkeProcessingProbe probe = new DoubleSkeProcessingProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received neither alert nor finished handshake. Last message: SERVER_HELLO_DONE",
                report.getResult(
                                WebRtcProperties
                                        .NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_CONTINUOUS_SQN)
                        .toString());
        assertEquals(
                "TRUE, Received neither alert nor finished handshake. Last message: SERVER_HELLO_DONE",
                report.getResult(
                                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_SAME_SQN)
                        .toString());
    }

    /**
     * Tests whether abandoned handshake by alert is correctly detected
     *
     * @throws IOException
     */
    @Test
    public void testVerifyingViaAlert() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions,
                        SimulationLibrary.INDEX_ID_SCCS,
                        SimulationLibrary.INDEX_ID_CKEX,
                        SimulationLibrary.INDEX_ID_CA);
        actions.add(SimulatedAction.alertBadCert(500, ConnectionSide.CLIENT));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        DoubleSkeProcessingProbe probe = new DoubleSkeProcessingProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(
                                WebRtcProperties
                                        .NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_CONTINUOUS_SQN)
                        .toString());
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(
                                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_SAME_SQN)
                        .toString());
    }
}
