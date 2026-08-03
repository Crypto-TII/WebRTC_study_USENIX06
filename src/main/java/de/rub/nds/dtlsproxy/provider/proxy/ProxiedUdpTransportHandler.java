/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import de.rub.nds.dtlsproxy.packet.PacketCaptureController;
import de.rub.nds.protocol.exception.TimeoutException;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

public class ProxiedUdpTransportHandler extends UdpTransportHandler {

    private Logger LOGGER = LogManager.getLogger();

    private PcapHandle pcapHandle;
    private BlockingQueue<byte[]> incomingPacketQueue;

    private InetAddress dstAddr;
    private InetAddress srcAddr;
    private int dstPort;
    private int srcPort;
    private MacAddress destinationMacAddress;
    private MacAddress sourceMacAddress;

    public ProxiedUdpTransportHandler(
            BlockingQueue<byte[]> incomingPacketQueue,
            PcapHandle pcapHandle,
            Connection con,
            InetAddress srcAddress,
            InetAddress dstAddr,
            int srcPort,
            int dstPort,
            MacAddress sourceMacAddress,
            MacAddress destinationMacAddress) {
        super(con);
        this.pcapHandle = pcapHandle;
        this.incomingPacketQueue = incomingPacketQueue;
        this.srcAddr = srcAddress;
        this.dstAddr = dstAddr;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.destinationMacAddress = destinationMacAddress;
        this.sourceMacAddress = sourceMacAddress;
    }

    @Override
    public void closeConnection() throws IOException {}

    @Override
    public void closeClientConnection() throws IOException {}

    @Override
    public void preInitialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        LOGGER.trace(
                "Sending data from {}:{} to {}:{} via pcap4j: {}",
                srcAddr,
                srcPort,
                dstAddr,
                dstPort,
                data);
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .correctChecksumAtBuild(true)
                .srcAddr(srcAddr)
                .dstAddr(dstAddr)
                .srcPort(UdpPort.getInstance((short) srcPort))
                .dstPort(UdpPort.getInstance((short) dstPort))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(new UnknownPacket.Builder().rawData(data));

        // Build the UDP packet
        Packet udpPacket = udpBuilder.build();

        final IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder();
        ipv4Builder
                .dstAddr((Inet4Address) dstAddr)
                .srcAddr((Inet4Address) srcAddr)
                .payloadBuilder(udpPacket.getBuilder())
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
                .ttl((byte) 127)
                .correctLengthAtBuild(true)
                .correctChecksumAtBuild(true)
                .protocol(IpNumber.UDP);

        // Build the IPv4 packet and let pcap4j automatically fill in the source IP address
        final IpV4Packet ipv4Packet = ipv4Builder.build();
        final EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.payloadBuilder(ipv4Packet.getBuilder());
        etherBuilder.srcAddr(sourceMacAddress);
        etherBuilder.type(EtherType.IPV4);
        etherBuilder.dstAddr(destinationMacAddress);
        etherBuilder.paddingAtBuild(true);
        // Build the Ethernet packet and let pcap4j automatically fill in the source and destination
        // MAC addresses
        final EthernetPacket etherPacket = etherBuilder.build();

        // Send the Ethernet frame

        try {
            PacketCaptureController.capturePacket(etherPacket);
            pcapHandle.sendPacket(etherPacket);
        } catch (Exception e) {
            throw new IOException("Failed to send packet", e);
        }
    }

    @Override
    public byte[] fetchData() throws IOException {
        try {
            byte[] data = incomingPacketQueue.poll(timeout, TimeUnit.MILLISECONDS);
            if (data == null) {
                throw new TimeoutException("Did not receive a packet in time");
            } else {
                return data;
            }
        } catch (InterruptedException ex) {
            throw new TimeoutException("Did not receive a packet in time");
        }
    }

    @Override
    public byte[] fetchData(int amountOfData) throws IOException {
        throw new UnsupportedOperationException("Unimplemented method 'fetchData(amount of Data)'");
    }

    @Override
    public boolean isClosed() throws IOException {
        return false;
    }

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }
}
