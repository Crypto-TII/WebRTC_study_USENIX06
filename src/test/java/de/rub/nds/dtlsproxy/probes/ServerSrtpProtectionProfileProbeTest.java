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
import de.rub.nds.dtlsproxy.probes.dtls.ServerSrtpProtectionProfileProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ServerSrtpProtectionProfileProbeTest extends ProbingTest {

    /**
     * Tests if a SrtpProtectionProfileProbe run completes or if it results in a deadlock
     *
     * @throws IOException
     */
    @Test
    public void profileSelectionTest() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(
                                SimulationLibrary.remove(
                                        SimulationLibrary.FULL_HS_SERVER_SIDE,
                                        SimulationLibrary.INDEX_ID_CH)));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ServerSrtpProtectionProfileProbe probe =
                new ServerSrtpProtectionProfileProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                Arrays.asList(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80),
                report.getServerSupportedProtectionProfiles());
    }
}
