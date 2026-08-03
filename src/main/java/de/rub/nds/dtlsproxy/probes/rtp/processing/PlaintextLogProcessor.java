/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import jakarta.xml.bind.DatatypeConverter;
import java.io.IOException;

public class PlaintextLogProcessor extends Processor {

    private final boolean serverToClient;
    private final String protocolName;

    public PlaintextLogProcessor(boolean serverToClient, String protocolName) {
        this.serverToClient = serverToClient;
        this.protocolName = protocolName;
    }

    @Override
    protected void process(byte[] data) throws IOException {
        LOGGER.debug(
                "{} {} plain: {}",
                serverToClient ? "serverToClient" : "clientToServer",
                protocolName,
                DatatypeConverter.printHexBinary(data));
        output(data);
    }
}
