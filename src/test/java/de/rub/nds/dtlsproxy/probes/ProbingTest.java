/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes;

import de.rub.nds.dtlsproxy.utils.ProbeConnectionHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.io.IOException;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

/** Basic construct for testing a Webrtc probe based on simulated input */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ProbingTest {

    private static final int TIMEOUT = 0;

    public ProbingTest() {
        ProviderUtil.addBouncyCastleProvider();
    }

    public ProbeConnectionHandler createConnectionHandler(Simulation simulation)
            throws IOException {
        try {
            return new ProbeConnectionHandler(simulation, TIMEOUT);
        } catch (NotOpenException | PcapNativeException e) {
            throw new RuntimeException("Failed to create connection handler", e);
        }
    }
}
