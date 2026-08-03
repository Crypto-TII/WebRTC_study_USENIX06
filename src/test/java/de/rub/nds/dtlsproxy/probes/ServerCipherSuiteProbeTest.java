/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.dtlsproxy.config.ConnectionConfig;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.probes.dtls.ServerCipherSuiteProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ServerCipherSuiteProbeTest extends ProbingTest {

    /**
     * Tests if a correct Server cipher suite selected
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
        report.setClientSupportedCipherSuites(
                List.of(
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        ServerCipherSuiteProbe probe = new ServerCipherSuiteProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                Arrays.asList(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
                report.getServerSupportedCipherSuites());
    }
}
