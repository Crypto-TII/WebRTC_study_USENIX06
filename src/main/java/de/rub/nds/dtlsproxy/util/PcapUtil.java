/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.packet.*;
import org.pcap4j.util.MacAddress;

public final class PcapUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    private PcapUtil() {}

    public static Packet correctSourceAddress(
            Packet packet,
            InetAddress newSourceAddress,
            MacAddress newSourceMacAddress,
            MacAddress newDestinationMacAddress) {
        if (newSourceAddress instanceof Inet4Address && packet.contains(IpV4Packet.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            // Create a new EthernetPacket with the modified source IP address and MAC address
            EthernetPacket.Builder modifiedEthernetBuilder = ethernetPacket.getBuilder();
            modifiedEthernetBuilder.srcAddr(newSourceMacAddress);
            modifiedEthernetBuilder.dstAddr(newDestinationMacAddress);
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            // Create a new IpV4Packet with the modified IP address
            IpV4Packet.Builder modifiedIpV4Builder = ipV4Packet.getBuilder();
            modifiedIpV4Builder = modifiedIpV4Builder.srcAddr((Inet4Address) newSourceAddress);
            modifiedIpV4Builder.correctChecksumAtBuild(true);
            modifiedIpV4Builder.correctLengthAtBuild(true);
            // Set the payload of the Ethernet layer to the modified IP packet
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpPacket.Builder modifiedUdpBuilder = udpPacket.getBuilder();
            modifiedUdpBuilder.correctChecksumAtBuild(true);
            modifiedUdpBuilder.correctLengthAtBuild(true);
            modifiedUdpBuilder.dstAddr(getDestinationAddress(packet));
            modifiedUdpBuilder.srcAddr(newSourceAddress);
            modifiedIpV4Builder.payloadBuilder(modifiedUdpBuilder);
            modifiedEthernetBuilder.payloadBuilder(modifiedIpV4Builder);
            return modifiedEthernetBuilder.build();
        } else if (newSourceAddress instanceof Inet6Address && packet.contains(IpV6Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else if (newSourceAddress instanceof Inet6Address && packet.contains(IpV4Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else if (newSourceAddress instanceof Inet4Address && packet.contains(IpV6Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else {
            throw new RuntimeException(
                    "Could not adjust destination IP - not sure what is going on. Not a network layer packet?");
        }
    }

    public static Packet correctDestinationAddress(
            Packet packet,
            InetAddress newDestinationIp,
            MacAddress newDesMacAddress,
            MacAddress newSourceMacAddress) {
        if (newDestinationIp instanceof Inet4Address && packet.contains(IpV4Packet.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            // Create a new EthernetPacket with the modified source IP address and MAC address
            EthernetPacket.Builder modifiedEthernetBuilder = ethernetPacket.getBuilder();
            modifiedEthernetBuilder.dstAddr(newDesMacAddress);
            modifiedEthernetBuilder.srcAddr(newSourceMacAddress);
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            // Create a new IpV4Packet with the modified IP address
            IpV4Packet.Builder modifiedIpV4Builder = ipV4Packet.getBuilder();
            modifiedIpV4Builder.dstAddr((Inet4Address) newDestinationIp);
            // TODO do we need this? (easier to test without)
            // modifiedIpV4Builder.ttl((byte) 127);
            modifiedIpV4Builder.correctChecksumAtBuild(true);
            modifiedIpV4Builder.correctLengthAtBuild(true);

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpPacket.Builder modifiedUdpBuilder = udpPacket.getBuilder();
            modifiedUdpBuilder.correctChecksumAtBuild(true);
            modifiedUdpBuilder.correctLengthAtBuild(true);
            modifiedUdpBuilder.dstAddr(newDestinationIp);
            modifiedUdpBuilder.srcAddr(getSourceAddress(packet));
            modifiedIpV4Builder.payloadBuilder(modifiedUdpBuilder);
            // Set the payload of the Ethernet layer to the modified IP packet
            modifiedEthernetBuilder.payloadBuilder(modifiedIpV4Builder);
            return modifiedEthernetBuilder.build();
        } else if (newDestinationIp instanceof Inet6Address && packet.contains(IpV6Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else if (newDestinationIp instanceof Inet6Address && packet.contains(IpV4Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else if (newDestinationIp instanceof Inet4Address && packet.contains(IpV6Packet.class)) {
            LOGGER.trace("Not forwardable as of now");
            return packet;
        } else {
            throw new RuntimeException(
                    "Could not adjust destination IP - not sure what is going on");
        }
    }

    public static InetAddress getDestinationAddress(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            return packet.get(IpV4Packet.class).getHeader().getDstAddr();
        } else if (packet.contains(IpV6Packet.class)) {
            return packet.get(IpV6Packet.class).getHeader().getDstAddr();
        } else {
            throw new RuntimeException("Received UDP packet thats neither IPv4 nor IPv6. Aborting");
        }
    }

    public static InetAddress getSourceAddress(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            return packet.get(IpV4Packet.class).getHeader().getSrcAddr();
        } else if (packet.contains(IpV6Packet.class)) {
            return packet.get(IpV6Packet.class).getHeader().getSrcAddr();
        } else {
            throw new RuntimeException("Received UDP packet thats neither IPv4 nor IPv6. Aborting");
        }
    }
}
