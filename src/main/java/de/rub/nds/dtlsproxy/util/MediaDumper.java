/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.provider.proxy.ConnectionEntry;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

public class MediaDumper implements ByteArrayWriteout {

    protected static final Logger LOGGER = LogManager.getLogger();

    private PcapDumper dumper = null;

    private HookedConnection associatedConnection;

    private final boolean serverToClient;

    public MediaDumper(ProxyConfiguration config, boolean serverToClient, String probeName)
            throws NotOpenException, PcapNativeException {

        this.serverToClient = serverToClient;

        if (!config.isDumpMedia()) {
            return;
        }

        if (config.getRecordingDirectory() == null) {
            throw new RuntimeException(
                    "Media dumping enabled, but no recording directory specified");
        }

        String filepath =
                config.getRecordingDirectory()
                        + File.separator
                        + probeName
                        + ".media."
                        + (serverToClient ? "serverToClient" : "clientToServer")
                        + ".pcap";

        dumper = createDumper(filepath);
    }

    @Override
    public void input(byte[] data) throws IOException {

        if (dumper == null) {
            // assume dumping not enabled
            return;
        }

        try {
            if (associatedConnection == null) {
                dumper.dumpRaw(data);
            } else {
                dumper.dump(createUdpPacket(data, associatedConnection, serverToClient));
            }
        } catch (Exception e) {
            LOGGER.warn("Failed dumping packet: ", e);
        }
    }

    private PcapDumper createDumper(String filepath) throws PcapNativeException, NotOpenException {

        PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);

        return handle.dumpOpen(filepath);
    }

    public void close() {
        if (dumper != null) {
            dumper.close();
        }
    }

    private static Packet createUdpPacket(
            byte[] udpPayload, HookedConnection connection, boolean serverToClient) {

        final ConnectionEntry entry = connection.getEntry();

        if (!connection.isInboundTheDtlsClient()) {
            // inverse interface naming
            serverToClient = !serverToClient;
        }

        final Inet4Address srcIpAddr =
                (Inet4Address)
                        (serverToClient ? entry.getOutboundTargetIp() : entry.getInboundTargetIp());
        final Inet4Address dstIpAddr =
                (Inet4Address)
                        (serverToClient ? entry.getInboundTargetIp() : entry.getOutboundTargetIp());
        final MacAddress srcMacAddr =
                serverToClient
                        ? entry.getOutboundDestinationMacAddress()
                        : entry.getInboundDestinationMacAddress();
        final MacAddress dstMacAddr =
                serverToClient
                        ? entry.getInboundDestinationMacAddress()
                        : entry.getOutboundDestinationMacAddress();

        // Create UDP packet
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .dstPort(new UdpPort((short) entry.getRemotePort(), "remote"))
                .srcPort(new UdpPort((short) entry.getLocalPort(), "local"))
                .payloadBuilder(new UnknownPacket.Builder().rawData(udpPayload))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .srcAddr(srcIpAddr)
                .dstAddr(dstIpAddr);

        // Create IP packet
        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(srcIpAddr)
                .dstAddr(dstIpAddr)
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        // Create Ethernet frame
        EthernetPacket.Builder ethernetBuilder = new EthernetPacket.Builder();
        ethernetBuilder
                .dstAddr(dstMacAddr)
                .srcAddr(srcMacAddr)
                .type(EtherType.IPV4)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);

        // Build the packet
        return ethernetBuilder.build();
    }

    public HookedConnection getAssociatedConnection() {
        return associatedConnection;
    }

    public void setAssociatedConnection(HookedConnection associatedConnection) {
        this.associatedConnection = associatedConnection;
    }
}
