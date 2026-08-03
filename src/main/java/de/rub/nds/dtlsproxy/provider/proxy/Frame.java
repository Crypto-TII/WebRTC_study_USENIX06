/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import java.net.InetAddress;

public class Frame {

    private final InetAddress destinationAddress;
    private final InetAddress sourceAddress;
    private final int sourcePort;
    private final int destinationPort;
    private final byte[] payload;

    public Frame(
            InetAddress destinationAddress,
            InetAddress sourceAddress,
            int sourcePort,
            int destinationPort,
            byte[] payload) {
        this.destinationAddress = destinationAddress;
        this.sourceAddress = sourceAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.payload = payload;
    }

    public byte[] getPayload() {
        return payload;
    }

    public InetAddress getDestinationAddress() {
        return destinationAddress;
    }

    public InetAddress getSourceAddress() {
        return sourceAddress;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }
}
