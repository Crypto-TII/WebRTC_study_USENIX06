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
import de.rub.nds.dtlsproxy.probes.dtls.ProviderTestProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import de.rub.nds.scanner.core.probe.result.TestResults;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProviderTestProbeTest extends ProbingTest {

    /**
     * Tests if provider acknowledged as functional
     *
     * @throws IOException
     */
    @Test
    public void providerFunctional() throws IOException {

        ProbeConnectionHandler handler =
                createConnectionHandler(
                        Simulation.repeating(SimulationLibrary.FULL_HS_CLIENT_SIDE));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        report.putResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));
        ProviderTestProbe probe = new ProviderTestProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(TestResults.TRUE, report.getResult(WebRtcProperties.PROVIDER_FUNCTIONAL));
    }
}
