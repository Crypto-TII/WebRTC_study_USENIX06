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
import de.rub.nds.dtlsproxy.probes.dtls.ServerVerifiesCertificatesProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ServerVerifiesCertificatesProbeTest extends ProbingTest {

    /**
     * Tests whether missing verification is detected
     *
     * @throws IOException
     */
    @Test
    public void testNotVerifyingViaFullHandshake() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(SimulationLibrary.FULL_HS_SERVER_SIDE));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultServerSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        report.setDefaultClientSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ServerVerifiesCertificatesProbe probe =
                new ServerVerifiesCertificatesProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                new DetailedResult<>(TestResults.FALSE, "Finished handshake"),
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CERTIFICATE));
    }

    /**
     * Tests wether present verification is detected when the handshake is abandoned by the server
     *
     * @throws IOException
     */
    @Test
    public void testVerifyingViaAbort() throws IOException {

        List<SimulatedAction> actions =
                SimulationLibrary.remove(
                        SimulationLibrary.FULL_HS_SERVER_SIDE, SimulationLibrary.INDEX_ID_SCCS);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultServerSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        report.setDefaultClientSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ServerVerifiesCertificatesProbe probe =
                new ServerVerifiesCertificatesProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CERTIFICATE).toString());
    }

    /**
     * Tests wether present verification is detected when alert is send from server
     *
     * @throws IOException
     */
    @Test
    public void testVerifyingViaAlert() throws IOException {

        List<SimulatedAction> actions =
                SimulationLibrary.remove(
                        SimulationLibrary.FULL_HS_SERVER_SIDE, SimulationLibrary.INDEX_ID_SCCS);
        actions.add(SimulatedAction.alertBadCert(600, ConnectionSide.SERVER));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));
        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultServerSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        report.setDefaultClientSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ServerVerifiesCertificatesProbe probe =
                new ServerVerifiesCertificatesProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CERTIFICATE).toString());
    }
}
