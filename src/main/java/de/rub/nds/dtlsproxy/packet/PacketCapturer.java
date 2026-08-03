/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.packet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class PacketCapturer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PcapDumper dumper;

    public PacketCapturer(PcapDumper dumper) {
        this.dumper = dumper;
    }

    public void capture(Packet packet) {
        try {
            dumper.dump(packet);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    public void close() {
        dumper.close();
    }
}
