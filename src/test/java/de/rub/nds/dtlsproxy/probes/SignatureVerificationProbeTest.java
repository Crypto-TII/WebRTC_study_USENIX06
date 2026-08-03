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
import de.rub.nds.dtlsproxy.probes.dtls.SignatureVerificationProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SignatureVerificationProbeTest extends ProbingTest {

    /**
     * Tests signature verifications flagged as failed when handshake proceeds
     *
     * @throws IOException
     */
    @Test
    public void testSignatureVerificationViaFullHandshake() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions = SimulationLibrary.remove(actions, SimulationLibrary.INDEX_ID_CA);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                TestResults.FALSE, report.getResult(WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE));
    }

    /**
     * Tests is the probes aborts if no certificate was requested
     *
     * @throws IOException
     */
    @Test
    public void testSignatureVerificationNoCertRequest() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions = SimulationLibrary.remove(actions, SimulationLibrary.INDEX_ID_CA);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        report.putResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, Boolean.FALSE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                TestResults.CANNOT_BE_TESTED,
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE));
        assertEquals(
                TestResults.CANNOT_BE_TESTED,
                report.getResult(WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE));
        assertEquals(
                TestResults.CANNOT_BE_TESTED,
                report.getResult(WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE));
    }

    /**
     * Tests wether verification detected when handshake abandoned on server side
     *
     * @throws IOException
     */
    @Test
    public void testServerSignatureVerificationSuccessViaAbort() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_SCCS);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE).toString());
    }

    /**
     * Tests wether verification detected when handshake abandoned on client side
     *
     * @throws IOException
     */
    @Test
    public void testClientSignatureVerificationSuccessViaAbort() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions,
                        SimulationLibrary.INDEX_ID_CA,
                        SimulationLibrary.INDEX_ID_SCCS,
                        SimulationLibrary.INDEX_ID_CKEX);

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received no alert. No proof. Last message: <no response>",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE).toString());
    }

    /**
     * Tests wether verification detected when handshake aborted on server side by alert
     *
     * @throws IOException
     */
    @Test
    public void testServerSignatureVerificationSuccessViaAlert() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_SCCS);
        actions.add(SimulatedAction.alertBadCert(600, ConnectionSide.SERVER));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        // If this doesn't pass, make sure you fixed the 'couldPop' in PopBufferedMessageAction
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE).toString());
    }

    /**
     * Tests wether verification detected when handshake aborted on client side by alert
     *
     * @throws IOException
     */
    @Test
    public void testClientSignatureVerificationSuccessViaAlert() throws IOException {

        List<SimulatedAction> actions = SimulationLibrary.FULL_HS;
        actions =
                SimulationLibrary.remove(
                        actions,
                        SimulationLibrary.INDEX_ID_CA,
                        SimulationLibrary.INDEX_ID_SCCS,
                        SimulationLibrary.INDEX_ID_CKEX);
        actions.add(SimulatedAction.alertBadCert(600, ConnectionSide.CLIENT));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = createReport();
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SignatureVerificationProbe probe = new SignatureVerificationProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE).toString());
        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE).toString());
    }

    private static WebRtcPlatformReport createReport() {
        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        report.putResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, TestResults.TRUE);
        report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
        report.putResult(WebRtcProperties.WANT_TO_TEST_CLIENT, TestResults.TRUE);
        report.putResult(WebRtcProperties.WANT_TO_TEST_SERVER, TestResults.TRUE);
        report.setDefaultClientSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        report.setDefaultServerSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.ECDSA_SHA256);
        return report;
    }
}
