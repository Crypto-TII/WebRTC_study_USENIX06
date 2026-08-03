/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.FULL_HS;
import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.FULL_HS_NO_CR;
import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.INDEX_ID_CA;
import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.INDEX_ID_CKEX;
import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.INDEX_ID_SCCS;
import static de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary.remove;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.dtlsproxy.config.ConnectionConfig;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.dtls.SelfTestProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import java.io.IOException;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SelfTestProbeTest extends ProbingTest {

    /**
     * Tests if setup acknowledged as fully functional
     *
     * @throws IOException
     */
    @Test
    public void testFullyFunctional() throws IOException {

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(FULL_HS));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.OUTBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SelfTestProbe probe = new SelfTestProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.CLIENT_FUNCTIONAL));
        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.SERVER_FUNCTIONAL));
        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.COMPLETELY_FUNCTIONAL));
        assertEquals(
                TestResults.TRUE, report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST));
        assertEquals(256, report.getDefaultSignatureLength());
        // TODO: Reintroduce Signature and hash check, using fitting data
        /*
        assertEquals(
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                report.getDefaultSelectedSignatureAndHashAlgorithm());*/
        assertEquals(NamedGroup.ECDH_X25519, report.getDefaultSelectedNamedGroup());
        // TODO: add check for certificate chain
        assertEquals(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                report.getDefaultSelectedCipherSuite());
        assertEquals(ProtocolVersion.DTLS12, report.getDefaultSelectedProtocolVersion());
        assertEquals(CompressionMethod.NULL, report.getDefaultSelectedCompressionMethod());
        assertEquals(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
                report.getDefaultSelectedSrtpProtectionProfile());
        assertEquals(
                Set.of(
                        ExtensionType.RENEGOTIATION_INFO,
                        ExtensionType.EC_POINT_FORMATS,
                        ExtensionType.SESSION_TICKET,
                        ExtensionType.USE_SRTP,
                        ExtensionType.EXTENDED_MASTER_SECRET),
                report.getNegotiatedExtensions());
    }

    /**
     * Tests if missing cert request from serer noticed
     *
     * @throws IOException
     */
    @Test
    public void testMissingCertRequestDetected() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(Simulation.repeating(FULL_HS_NO_CR));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        SelfTestProbe probe = new SelfTestProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.CLIENT_FUNCTIONAL));
        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.SERVER_FUNCTIONAL));
        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.COMPLETELY_FUNCTIONAL));
        assertEquals(
                TestResults.FALSE, report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE));
        assertEquals(
                TestResults.FALSE,
                report.getResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST));
    }

    /**
     * Tests wether it is detected that a Client Key Exchange is missing
     *
     * @throws IOException
     */
    @Test
    public void testBrokenForwardingAcknowledged() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(
                                remove(FULL_HS, INDEX_ID_CKEX, INDEX_ID_SCCS, INDEX_ID_CA)));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        report.putResult(WebRtcProperties.PROVIDER_FUNCTIONAL, TestResults.TRUE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        SelfTestProbe probe = new SelfTestProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.CLIENT_FUNCTIONAL));
        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.SERVER_FUNCTIONAL));
        assertEquals(
                TestResults.PARTIALLY, report.getResult(WebRtcProperties.COMPLETELY_FUNCTIONAL));
    }
}
