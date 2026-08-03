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
import de.rub.nds.dtlsproxy.probes.dtls.EarlyResumptionAuthBypassProbe;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.utils.PacketLibrary;
import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.ConnectionSide;
import de.rub.nds.dtlsproxy.utils.simulate.SimulatedAction;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.dtlsproxy.utils.simulate.SimulationLibrary;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class EarlyResumptionAuthBypassProbeTest extends ProbingTest {

    /**
     * Tests resumption flaged as successfull if handshaked proceeds to changecipherspec message
     * from server
     *
     * @throws IOException
     */
    @Test
    public void testResumptionSuccessViaFullHandshake() throws IOException {
        List<SimulatedAction> actions = new ArrayList<>(SimulationLibrary.FULL_HS);
        actions = SimulationLibrary.remove(actions, SimulationLibrary.INDEX_ID_CA);
        actions.add(
                new SimulatedAction(
                        600,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS,
                        "sh 2"));
        actions.add(
                new SimulatedAction(
                        601,
                        ConnectionSide.SERVER,
                        PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_2,
                        "sh 2 cont"));
        actions.add(
                new SimulatedAction(
                        602,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_SESSION_TICKET_CCS_3,
                        "css 2"));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        EarlyResumptionAuthBypassProbe probe =
                new EarlyResumptionAuthBypassProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "FALSE, Vulnerable, server allowed early resumption",
                report.getResult(WebRtcProperties.NO_EARLY_RESUMPTION_IDS).toString());
    }

    /**
     * Tests wether resumption fail correctly flagged if only ch send after reset
     *
     * @throws IOException
     */
    @Test
    public void testResumptionSuccessViaAbort() throws IOException {

        List<SimulatedAction> actions = new ArrayList<>(SimulationLibrary.FULL_HS);
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_SCCS);
        actions.add(
                new SimulatedAction(
                        600,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS,
                        "sh 2"));
        actions.add(
                new SimulatedAction(
                        601,
                        ConnectionSide.SERVER,
                        PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_2,
                        "sh 2 cont"));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        EarlyResumptionAuthBypassProbe probe =
                new EarlyResumptionAuthBypassProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received neither alert nor finished handshake. Last message: SERVER_HELLO_DONE",
                report.getResult(WebRtcProperties.NO_EARLY_RESUMPTION_IDS).toString());
    }

    /**
     * Tests wether resumption fail correctly flagged if abort send after reset
     *
     * @throws IOException
     */
    @Test
    public void testResumptionSuccessViaAlert() throws IOException {
        List<SimulatedAction> actions = new ArrayList<>(SimulationLibrary.FULL_HS);
        actions =
                SimulationLibrary.remove(
                        actions, SimulationLibrary.INDEX_ID_CA, SimulationLibrary.INDEX_ID_SCCS);
        actions.add(
                new SimulatedAction(
                        600,
                        ConnectionSide.SERVER,
                        PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS,
                        "sh 2"));
        actions.add(
                new SimulatedAction(
                        601,
                        ConnectionSide.SERVER,
                        PacketLibrary.CERTIFICATE_FRAGMENTS_CONTINUATION_2,
                        "sh 2 cont"));
        actions.add(SimulatedAction.alertBadCert(602, ConnectionSide.SERVER));

        ProbeConnectionHandler handler = createConnectionHandler(Simulation.repeating(actions));

        WebRtcPlatformReport report = new WebRtcPlatformReport("", FilterDirection.INBOUND);
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        report,
                        handler.getProvider(),
                        new SessionManager(new ConnectionConfig()));

        EarlyResumptionAuthBypassProbe probe =
                new EarlyResumptionAuthBypassProbe(webrtcExecutionContext);
        probe.test(report);

        assertEquals(
                "TRUE, Received alert message: Alert(FATAL,BAD_CERTIFICATE)",
                report.getResult(WebRtcProperties.NO_EARLY_RESUMPTION_IDS).toString());
    }
}
