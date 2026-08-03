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
import org.pcap4j.util.MacAddress;

public class ConnectionEntry {

    private final InetAddress inboundIp;
    private final InetAddress outboundIp;
    private final InetAddress outboundTargetIp;
    private final InetAddress inboundTargetIp;
    private final int localPort;
    private final int remotePort;
    private final MacAddress inboundSourceMacAddress;
    private final MacAddress inboundDestinationMacAddress;
    private final MacAddress outboundSourceMacAddress;
    private final MacAddress outboundDestinationMacAddress;

    public ConnectionEntry(
            InetAddress inboundIp,
            InetAddress outboundIp,
            InetAddress outboundTargetIp,
            InetAddress inboundTargetIp,
            int localPort,
            int remotePort,
            MacAddress inboundSourceMacAddress,
            MacAddress inboundDestinationMacAddress,
            MacAddress outboundSourceMacAddress,
            MacAddress outboundDestinationMacAddress) {
        this.inboundIp = inboundIp;
        this.inboundTargetIp = inboundTargetIp;
        this.outboundTargetIp = outboundTargetIp;
        this.outboundIp = outboundIp;
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.inboundSourceMacAddress = inboundSourceMacAddress;
        this.inboundDestinationMacAddress = inboundDestinationMacAddress;
        this.outboundSourceMacAddress = outboundSourceMacAddress;
        this.outboundDestinationMacAddress = outboundDestinationMacAddress;
    }

    public InetAddress getInboundIp() {
        return inboundIp;
    }

    public InetAddress getOutboundIp() {
        return outboundIp;
    }

    public InetAddress getOutboundTargetIp() {
        return outboundTargetIp;
    }

    public InetAddress getInboundTargetIp() {
        return inboundTargetIp;
    }

    public int getLocalPort() {
        return localPort;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public MacAddress getInboundSourceMacAddress() {
        return inboundSourceMacAddress;
    }

    public MacAddress getInboundDestinationMacAddress() {
        return inboundDestinationMacAddress;
    }

    public MacAddress getOutboundSourceMacAddress() {
        return outboundSourceMacAddress;
    }

    public MacAddress getOutboundDestinationMacAddress() {
        return outboundDestinationMacAddress;
    }

    @Override
    public int hashCode() {
        int localHostHash =
                0; // ignore local addr because issues with determining local addr and it's always
        // the same anyways
        int remoteHostHash =
                outboundTargetIp.getAddress()[0]
                        + (1 << 8) * outboundTargetIp.getAddress()[1]
                        + (1 << 16) * outboundTargetIp.getAddress()[2]
                        + (1 << 24) * outboundTargetIp.getAddress()[3];
        return localHostHash ^ remoteHostHash ^ localPort ^ remotePort;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ConnectionEntry other = (ConnectionEntry) obj;
        return this.localPort == other.localPort && this.remotePort == other.remotePort;
    }

    @Override
    public String toString() {
        return "Inbound:"
                + inboundIp.getHostAddress()
                + ":"
                + localPort
                + ", Oubound: "
                + outboundIp.getHostAddress()
                + ", Target: "
                + outboundTargetIp.getHostAddress()
                + ":"
                + remotePort;
    }
}
