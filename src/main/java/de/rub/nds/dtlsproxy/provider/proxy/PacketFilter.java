/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.packet.PacketCaptureController;
import de.rub.nds.dtlsproxy.packet.ParserUtil;
import de.rub.nds.dtlsproxy.provider.StunAddress;
import de.rub.nds.dtlsproxy.util.PcapUtil;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import jakarta.xml.bind.DatatypeConverter;
import java.net.Inet4Address;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapHandle.PcapDirection;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

/** PacketFilters need to be initialized first, then linked, then started */
public class PacketFilter {

    private static final int UDP_SNAP_LEN = 1500;
    private static final int KERNEL_TIMEOUT = 5;

    // blocking mode with timeout 5 ms: forwarding delay 6ms, non blocking mode: 18ms (but easier
    // shutdown)
    private static final boolean USE_NONBLOCKING_MODE = false;

    private static final String FILTER_EXPRESSION =
            "udp and not udp src port 5353 and not udp dst port 5353 and not udp src port 137 and not udp dst port 137 and not udp src port 53 and not udp dst port 53 and not udp src port 1900 and not udp dst port 1900";

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean shutdown = false;

    private final PcapHandle receivePcapHandle;
    private final PcapHandle forwardPcapHandle;

    private final SessionManager sessionManager;

    private final String receiveFromInterface;
    private final String forwardToInterface;

    private final Inet4Address receiveFromInterfaceSourceIp;
    private final MacAddress receiveFromInterfaceSourceMac;

    private final Inet4Address forwardToInterfaceSourceIp;
    private final MacAddress forwardToInterfaceSourceMac;
    private final Inet4Address inboundForwardToIp;
    private final MacAddress inboundForwardToMac;
    private final MacAddress outboundGatewayMac;

    private final FilterDirection direction;

    private final ProxyConfiguration proxyConfiguration;

    private Thread filterThread;

    public PacketFilter(
            ProxyConfiguration proxyConfiguration,
            FilterDirection direction,
            SessionManager sessionManager,
            String receiveFromInterface,
            String forwardToInterface,
            Inet4Address receiveFromInterfaceSourceIp,
            MacAddress receiveFromInterfaceSourceMac,
            Inet4Address forwardToInterfaceSourceIp,
            MacAddress forwardToInterfaceSourceMac,
            Inet4Address inboundForwardToIp,
            MacAddress inboundForwardToMac,
            MacAddress outboundGatewayMac) {
        this.proxyConfiguration = proxyConfiguration;
        this.sessionManager = sessionManager;
        this.receiveFromInterface = receiveFromInterface;
        this.forwardToInterface = forwardToInterface;
        this.receiveFromInterfaceSourceIp = receiveFromInterfaceSourceIp;
        this.receiveFromInterfaceSourceMac = receiveFromInterfaceSourceMac;
        this.forwardToInterfaceSourceIp = forwardToInterfaceSourceIp;
        this.forwardToInterfaceSourceMac = forwardToInterfaceSourceMac;
        this.inboundForwardToIp = inboundForwardToIp;
        this.inboundForwardToMac = inboundForwardToMac;
        this.outboundGatewayMac = outboundGatewayMac;
        this.direction = direction;
        PcapNetworkInterface networkInterface;
        try {
            networkInterface = Pcaps.getDevByName(receiveFromInterface);
            receivePcapHandle = prepareReceivingPcapHandle(networkInterface);
            networkInterface = Pcaps.getDevByName(forwardToInterface);
            forwardPcapHandle = prepareSendingPcapHandle(networkInterface);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        if (USE_NONBLOCKING_MODE) {
            try {
                receivePcapHandle.setBlockingMode(PcapHandle.BlockingMode.NONBLOCKING);
                forwardPcapHandle.setBlockingMode(PcapHandle.BlockingMode.NONBLOCKING);
            } catch (PcapNativeException | NotOpenException e) {
                throw new RuntimeException(e);
            }
        }

        // Overwrite global dump handle for packet logging
        PacketCaptureController.setDumpHandle(receivePcapHandle);

        logInternals();

        // force init of tls-attacker internal (stun) parsing
        logDummyPacket();
    }

    private void logInternals() {
        LOGGER.debug("Packet Filter - Direction: {}", direction);
        LOGGER.debug("Receive from interface: {}", receiveFromInterface);
        LOGGER.debug("Forward to interface: {}", forwardToInterface);
        LOGGER.debug("Receive from interface source IP: {}", receiveFromInterfaceSourceIp);
        LOGGER.debug("Receive from interface source MAC: {}", receiveFromInterfaceSourceMac);
        LOGGER.debug("Forward to interface source IP: {}", forwardToInterfaceSourceIp);
        LOGGER.debug("Forward to interface source MAC: {}", forwardToInterfaceSourceMac);
        LOGGER.debug("Inbound forward to IP: {}", inboundForwardToIp);
        LOGGER.debug("Inbound forward to MAC: {}", inboundForwardToMac);
        LOGGER.debug("Outbound gateway MAC: {}", outboundGatewayMac);
    }

    public String getReceiveFromInterface() {
        return receiveFromInterface;
    }

    public String getForwardToInterface() {
        return forwardToInterface;
    }

    public Inet4Address getReceiveFromInterfaceSourceIp() {
        return receiveFromInterfaceSourceIp;
    }

    public MacAddress getReceiveFromInterfaceSourceMac() {
        return receiveFromInterfaceSourceMac;
    }

    public Inet4Address getForwardToInterfaceSourceIp() {
        return forwardToInterfaceSourceIp;
    }

    public MacAddress getForwardToInterfaceSourceMac() {
        return forwardToInterfaceSourceMac;
    }

    protected ConnectionEntry createConnectionEntry(
            Inet4Address outboundToIp, int localPort, int remotePort) {
        if (direction == FilterDirection.INBOUND) {
            return new ConnectionEntry(
                    receiveFromInterfaceSourceIp,
                    forwardToInterfaceSourceIp,
                    outboundToIp,
                    inboundForwardToIp,
                    localPort,
                    remotePort,
                    receiveFromInterfaceSourceMac,
                    inboundForwardToMac,
                    forwardToInterfaceSourceMac,
                    outboundGatewayMac);
        } else {
            return new ConnectionEntry(
                    forwardToInterfaceSourceIp,
                    receiveFromInterfaceSourceIp,
                    outboundToIp,
                    inboundForwardToIp,
                    localPort,
                    remotePort,
                    forwardToInterfaceSourceMac,
                    inboundForwardToMac,
                    receiveFromInterfaceSourceMac,
                    outboundGatewayMac);
        }
    }

    public HookedConnection createHookedConnection(
            ConnectionEntry connectionEntry, FilterDirection filterDirection, StunAddress address) {
        try {
            HookedConnection connection;
            if (direction == FilterDirection.INBOUND) {
                connection =
                        new HookedConnection(
                                connectionEntry,
                                (int) proxyConfiguration.getTimeout(),
                                filterDirection,
                                receivePcapHandle,
                                forwardPcapHandle);
            } else {
                connection =
                        new HookedConnection(
                                connectionEntry,
                                (int) proxyConfiguration.getTimeout(),
                                filterDirection,
                                forwardPcapHandle,
                                receivePcapHandle);
            }
            if (address != null) {
                connection.setTurnMappedConnectionIp(address.getAddress());
                connection.setTurnMappedConnectionPort(address.getPort());
                connection.setUsingTurn(true);
            }
            return connection;
        } catch (Exception E) {
            throw new RuntimeException("Could not create hooked connection", E);
        }
    }

    protected PcapHandle prepareReceivingPcapHandle(PcapNetworkInterface networkInterface) {
        try {
            LOGGER.debug(
                    "Opening input network interface {} for input ({})",
                    networkInterface.getName(),
                    networkInterface.getDescription());

            PcapHandle tempPcapHandle =
                    new PcapHandle.Builder(networkInterface.getName())
                            .snaplen(UDP_SNAP_LEN)
                            .promiscuousMode(PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS)
                            .timeoutMillis(KERNEL_TIMEOUT) // timeout for dispatch()
                            .build();

            tempPcapHandle.setDirection(PcapHandle.PcapDirection.IN);
            tempPcapHandle.setFilter(FILTER_EXPRESSION, BpfProgram.BpfCompileMode.OPTIMIZE);
            return tempPcapHandle;
        } catch (Exception e) {
            throw new RuntimeException("Could not open network interface", e);
        }
    }

    protected PcapHandle prepareSendingPcapHandle(PcapNetworkInterface networkInterface) {
        try {
            LOGGER.debug(
                    networkInterface.getName() + " (" + networkInterface.getDescription() + ")");

            LOGGER.trace("Opening forward to network interface...");
            PcapHandle tempPcapHandle =
                    networkInterface.openLive(65536, PromiscuousMode.PROMISCUOUS, 1);
            tempPcapHandle.setDirection(PcapDirection.OUT);
            return tempPcapHandle;
        } catch (Exception e) {
            throw new RuntimeException("Could not open network interface", e);
        }
    }

    protected void handlePacket(Packet packet) {
        try {
            if (packet == null) {
                return;
            }

            if (!isUdpAndIpv4(packet)) {
                return; // Only supporting Ipv4 Udp
            }
            if (packet.getPayload() == null || packet.getPayload().getRawData() == null) {
                return; // Empty packets we do not care about.
            }
            // capture packet if instructed to
            PacketCaptureController.capturePacket(packet);

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket.getPayload() == null || udpPacket.getPayload().getRawData() == null) {
                return;
            }
            if (isFilteredPort(udpPacket.getHeader().getDstPort().valueAsInt())) {
                return;
            }
            if (isFilteredPort(udpPacket.getHeader().getSrcPort().valueAsInt())) {
                return;
            }

            logPacket(packet);

            // Do we care about this packet?

            List<PacketType> payloadLayers =
                    ParserUtil.classifyLayers(udpPacket.getPayload().getRawData());
            PacketType lastLayerType = payloadLayers.get(payloadLayers.size() - 1);

            if (lastLayerType == PacketType.UNKNOWN) {
                // we don't know what this is, we don't care
                forward(packet, lastLayerType);
                return;
            }

            ConnectionEntry entry = toConnectionEntry(packet);
            if (!proxyConfiguration.isAllowP2P()) {
                Inet4Address address;
                // If its a P2P connection, we do not want to handle it and forward it
                if (direction == FilterDirection.INBOUND) {
                    // Check if we are supposed to forward it to a local address
                    address = (Inet4Address) PcapUtil.getDestinationAddress(packet);
                } else {
                    // Check if its coming from a local address
                    address = (Inet4Address) PcapUtil.getSourceAddress(packet);
                }
                if (address.isAnyLocalAddress()
                        || address.isLinkLocalAddress()
                        || address.isSiteLocalAddress()
                        || address.isMulticastAddress()) {
                    forward(packet, lastLayerType);
                    return;
                }
            }

            if (sessionManager.isWhitelisted(entry)) {
                // this session was deemed not usable for analysis but is required to exist
                // TODO this will also forward RTP etc.
                //  we may want to analyse RTP while forwarding DTLS in the future
                LOGGER.trace(
                        "Packet belongs to whitelisted connection." + " Forwarding {}",
                        lastLayerType.name());
                forward(packet, lastLayerType);
                return;
            }

            HookedConnection connection = sessionManager.getConnection(entry);

            if (connection != null) {
                connection.updatePacketCount(payloadLayers, direction);
            }

            if (lastLayerType == PacketType.STUN) {
                // We check if this is trying to open a DataChannel
                // If so we just drop it (oops :) )
                try {
                    StunMessage message =
                            ParserUtil.parseStunMessage(udpPacket.getPayload().getRawData());
                    if (message.getMethodType() == StunMethodType.CHANNEL_BIND) {
                        LOGGER.debug("Dropping STUN Channel Bind request/response");
                        return;
                    }
                } catch (Exception E) {
                    LOGGER.debug(
                            "Could not parse packet as STUN message, likely not STUN. {} bytes",
                            udpPacket.getPayload().getRawData());
                }

                forward(packet, lastLayerType);
                return;
            }

            // packet is worth to process -> handle the connection

            // check if new entry required

            if (connection == null) {
                LOGGER.trace("Packet does not belong to existing connection");
                if (sessionManager.isBlacklisted(entry)) {
                    LOGGER.trace("Connection blacklisted. Skipping");
                    return;
                }
                if (!sessionManager.isConnectionMapEmpty()
                        && proxyConfiguration.isDisableConnectionStacking()) {
                    LOGGER.debug("Already having a hooked connection. Forwarding future ones");
                    forward(packet, lastLayerType);
                    return;
                }
                if (lastLayerType == PacketType.QUIC
                        || lastLayerType == PacketType.RTCP
                        || lastLayerType == PacketType.RTP
                        || lastLayerType == PacketType.TURN_CHANNEL
                        || lastLayerType == PacketType.DTLS_APP_DATA
                        || lastLayerType == PacketType.DTLS_ALERT
                        || lastLayerType == PacketType.DTLS_CHANGE_CIPHER_SPEC) {
                    // We do not create new connections for these packet types

                    forward(packet, lastLayerType);
                    return;
                }
                // Due to a browser bug(?) we have to additionally filter for the client hello
                // handshake message type
                // as the browser sometimes sends data from the wrong source port. This is a
                // workaround for this issue.
                if (!ParserUtil.carriesClientHello(udpPacket.getPayload().getRawData())) {
                    LOGGER.debug("Packet carries no ClientHello message. Skipping");
                    return;
                }
                // sanity check
                if (lastLayerType != PacketType.DTLS_HANDSHAKE) {
                    LOGGER.warn("Found non DTLS-HS packet that contains a CH. Somethings off");
                }

                // packet is from a new connection -> create new entry
                LOGGER.debug(
                        "Creating new connection for {} packet: src port: {} -> destination port {}, current protocol {}",
                        lastLayerType,
                        entry.getLocalPort(),
                        entry.getRemotePort(),
                        lastLayerType.name());
                StunAddress stunAddress =
                        ParserUtil.parseStunAddress(udpPacket.getPayload().getRawData());
                connection = createHookedConnection(entry, direction, stunAddress);
                // write DTLS data to the connection for it to be available for fingerprinting
                handleDtlsHandshake(udpPacket, connection);
                sessionManager.register(connection);
                // packet has been handled, continue with next
                return;
            }

            // TODO fix: if packet is CH, forward only happens with retransmissions
            if (!connection.isFilterActive()) {
                // forward any, but also queue for processing
                forward(packet, lastLayerType);
            }

            if (lastLayerType == PacketType.RTP) {
                // media packet
                handleRtp(udpPacket, connection);
                return;
            }

            if (lastLayerType == PacketType.RTCP) {
                // media control packet
                handleRtcp(udpPacket, connection);
                return;
            }

            if (lastLayerType == PacketType.DTLS_APP_DATA) {
                // media or app data on dtls
                handleDtlsAppData(udpPacket, connection);
                return;
            }

            if (lastLayerType == PacketType.DTLS_HANDSHAKE
                    || lastLayerType == PacketType.DTLS_ALERT
                    || lastLayerType == PacketType.DTLS_CHANGE_CIPHER_SPEC
                    || lastLayerType == PacketType.DTLS_MISC) {
                // mostly handshake related DTLS
                handleDtlsHandshake(udpPacket, connection);
                return;
            }

            LOGGER.warn("Encountered known but unhandled packet type");

        } catch (Exception e) {
            if (!shutdown) {
                // we care only about errors from analysis time
                LOGGER.error("Something went wrong processing UDP packets from " + "outside", e);
                throw new RuntimeException(e);
            }
        }
    }

    private Runnable createReceiveLoopRunnable() {
        return () -> {
            try {
                receivePcapHandle.loop(-1, this::handlePacket);
            } catch (InterruptedException | PcapNativeException | NotOpenException e) {
            } finally {
                // Close BOTH handles on this thread after the loop has returned.
                LOGGER.debug("Filter loop finished, closing pcap handles.");
                if (receivePcapHandle != null && receivePcapHandle.isOpen()) {
                    receivePcapHandle.close();
                }
                if (forwardPcapHandle != null && forwardPcapHandle.isOpen()) {
                    forwardPcapHandle.close();
                }
            }
        };
    }

    private ConnectionEntry toConnectionEntry(Packet packet) {

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        Inet4Address outboundToIpAddress;
        int localPort;
        int remotePort;
        if (direction == FilterDirection.OUTBOUND) {
            outboundToIpAddress = (Inet4Address) PcapUtil.getSourceAddress(packet);
            localPort = udpPacket.getHeader().getDstPort().valueAsInt();
            remotePort = udpPacket.getHeader().getSrcPort().valueAsInt();
        } else {
            outboundToIpAddress = (Inet4Address) PcapUtil.getDestinationAddress(packet);
            localPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            remotePort = udpPacket.getHeader().getDstPort().valueAsInt();
        }

        return createConnectionEntry(outboundToIpAddress, localPort, remotePort);
    }

    private void forward(Packet packet, PacketType type) {
        Packet toForwardPacket;
        try {

            if (direction == FilterDirection.INBOUND) {
                // If its an inbound packet, we have to adjust the source ip address and the MACs
                toForwardPacket =
                        PcapUtil.correctSourceAddress(
                                packet,
                                forwardToInterfaceSourceIp,
                                forwardToInterfaceSourceMac,
                                outboundGatewayMac);
            } else {
                // If its an outbound packet, we have to adjust the destination ip address and the
                // mac addresses
                toForwardPacket =
                        PcapUtil.correctDestinationAddress(
                                packet,
                                inboundForwardToIp,
                                inboundForwardToMac,
                                forwardToInterfaceSourceMac);
            }
            LOGGER.trace("Forwarding {}", type.name());
            PacketCaptureController.capturePacket(toForwardPacket);
            forwardPcapHandle.sendPacket(toForwardPacket);
        } catch (Exception e) {
            LOGGER.error("Failed to forward packet", e);
        }
    }

    private void handleRtp(UdpPacket udpPacket, HookedConnection connection)
            throws InterruptedException {
        LOGGER.trace("Process as RTP");
        if (direction == FilterDirection.INBOUND) {
            connection.getInboundRtp().put(udpPacket.getPayload().getRawData());
        } else {
            connection.getOutboundRtp().put(udpPacket.getPayload().getRawData());
        }
    }

    private void handleRtcp(UdpPacket udpPacket, HookedConnection connection)
            throws InterruptedException {
        LOGGER.trace("Process as RTCP");
        if (direction == FilterDirection.INBOUND) {
            connection.getInboundRtcp().put(udpPacket.getPayload().getRawData());
        } else {
            connection.getOutboundRtcp().put(udpPacket.getPayload().getRawData());
        }
    }

    private static boolean isUdp(Packet p) {
        IpPacket ip = p.get(IpPacket.class);
        return ip != null && ip.getHeader().getProtocol() == IpNumber.UDP;
    }

    private static boolean isUdpAndIpv4(Packet packet) {
        return packet.get(IpV4Packet.class) != null && isUdp(packet);
    }

    private boolean isFilteredPort(int port) {

        if (port == 5353 || port == 53 || port == 137 || port == 1900) {
            return true;
        }

        return false;
    }

    private void handleDtlsHandshake(UdpPacket udpPacket, HookedConnection connection)
            throws InterruptedException {
        LOGGER.trace("Process as handshake related DTLS");
        if (direction == FilterDirection.INBOUND) {
            connection.getInboundDtlsHandshake().put(udpPacket.getPayload().getRawData());
        } else {
            connection.getOutboundDtlsHandshake().put(udpPacket.getPayload().getRawData());
        }
    }

    private void handleDtlsAppData(UdpPacket udpPacket, HookedConnection connection)
            throws InterruptedException {
        LOGGER.trace("Process as DTLS application data");
        if (direction == FilterDirection.INBOUND) {
            connection.getInboundDtlsAppData().put(udpPacket.getPayload().getRawData());
        } else {
            connection.getOutboundDtlsAppData().put(udpPacket.getPayload().getRawData());
        }
    }

    public void startThread(String name) {
        this.filterThread = new Thread(createReceiveLoopRunnable(), name);
        this.filterThread.start();
    }

    public void shutdown() {

        // TODO pcap4j is a bit bugged, as in we need to send a packet to be received by the receive
        // handle so it would check wether it has to terminate. Regardless of our timeout. We can
        // avoid this by switching to NONBLOCKING mode but then we loose a great deal of performance
        // / increase the propagation delay. This shutdown method is a bit hacky, but it works ;))
        // (help)

        if (filterThread == null) {
            throw new NullPointerException("Filter thread is null");
        }

        LOGGER.debug("Shutting down packet filter... ({})", filterThread.getName());
        if (shutdown) {
            return; // Already shutting down
        }
        shutdown = true;

        // 1. Signal the loop to stop
        try {
            if (receivePcapHandle != null && receivePcapHandle.isOpen()) {
                receivePcapHandle.breakLoop();
            }
        } catch (NotOpenException ignored) {
            // This is fine, it's already closed.
        }

        filterThread.interrupt();

        // send bogus packets to cause loop termination.
        // whatever....
        new Thread(
                        () -> {
                            for (int i = 0; i < 15; i++) {
                                sendBogusUdpPacket();
                                try {
                                    Thread.sleep(200);
                                } catch (InterruptedException e) {
                                }
                            }
                        },
                        "T-800")
                .start();

        try {
            // no clue why, but specifying a timeout here is needed (race condition?)
            filterThread.join(2000);
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted while waiting for filter thread to terminate.", e);
            Thread.currentThread().interrupt(); // Restore the interrupted status
        }

        LOGGER.info("Packet filter ({}) has been shut down.", filterThread.getName());
    }

    private void sendBogusUdpPacket() {
        try {
            if (forwardPcapHandle != null && forwardPcapHandle.isOpen()) {
                // Create a minimal bogus UDP packet that will be captured by receivePcapHandle
                // Use a filtered port to ensure it gets dropped and doesn't interfere
                Packet bogusPacket =
                        createBogusUdpPacket(
                                receiveFromInterfaceSourceIp, receiveFromInterfaceSourceMac);
                if (bogusPacket != null) {
                    forwardPcapHandle.sendPacket(bogusPacket);
                    LOGGER.trace("Sent bogus UDP packet to help terminate receive loop");
                }
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to send bogus UDP packet during shutdown: {}", e.getMessage());
            // Not critical - the thread interrupt should still work as fallback
        }
    }

    private Packet createBogusUdpPacket(Inet4Address targetAddress, MacAddress targetMac) {
        try {
            byte[] emptyPayload = "end receiving".getBytes();

            // Create UDP packet
            UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
            udpBuilder
                    .dstPort(new UdpPort((short) 6666, "bogus"))
                    .srcPort(new UdpPort((short) 7777, "bogus"))
                    .payloadBuilder(new UnknownPacket.Builder().rawData(emptyPayload))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .srcAddr(targetAddress)
                    .dstAddr(targetAddress); // Send to self

            // Create IP packet
            IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
            ipBuilder
                    .version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl((byte) 64)
                    .protocol(IpNumber.UDP)
                    .srcAddr(targetAddress)
                    .dstAddr(targetAddress)
                    .payloadBuilder(udpBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            // Create Ethernet frame
            EthernetPacket.Builder ethernetBuilder = new EthernetPacket.Builder();
            ethernetBuilder
                    .dstAddr(targetMac)
                    .srcAddr(targetMac)
                    .type(EtherType.IPV4)
                    .payloadBuilder(ipBuilder)
                    .paddingAtBuild(true);

            return ethernetBuilder.build();
        } catch (Exception e) {
            LOGGER.debug("Failed to create bogus UDP packet: {}", e.getMessage());
            return null;
        }
    }

    public boolean isShutdown() {
        return shutdown;
    }

    private void logPacket(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (ParserUtil.isStun(udpPacket.getPayload().getRawData())) {
            logStunMessage(packet);
        } else {
            logRegularPacket(packet);
        }
    }

    private void logRegularPacket(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        LOGGER.trace(
                "[{}] {}:{} -> {}:{} ({} bytes)",
                direction,
                packet.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress(),
                udpPacket.getHeader().getSrcPort().valueAsInt(),
                packet.get(IpV4Packet.class).getHeader().getDstAddr().getHostAddress(),
                udpPacket.getHeader().getDstPort().valueAsInt(),
                udpPacket.getPayload().getRawData().length);
    }

    private void logStunMessage(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        try {
            StunMessage message = ParserUtil.parseStunMessage(udpPacket.getPayload().getRawData());
            LOGGER.debug(
                    "[{}] {}:{} -> {}:{}={}",
                    direction,
                    packet.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress(),
                    udpPacket.getHeader().getSrcPort().valueAsInt(),
                    packet.get(IpV4Packet.class).getHeader().getDstAddr().getHostAddress(),
                    udpPacket.getHeader().getDstPort().valueAsInt(),
                    message.toShortString());
        } catch (Exception E) {
            LOGGER.debug(
                    "Could not parse packet as STUN message, likely not STUN. {} bytes",
                    udpPacket.getPayload().getRawData().length);
            logRegularPacket(packet);
        }
    }

    private void logDummyPacket() {
        byte[] ipUdpStunBindingRequest =
                DatatypeConverter.parseHexBinary(
                        "45000080abbf40004011cd8c000000000000000000000000006ce60d000100502112a442554e3638345a4163615965640006000944474a743a6f75514e000000c057000400010000802a0008db3f69c1270cd1ec00250000002400046e7f1eff00080014c03e97627c99ebd15bfd02ead576baf1069d426e8028000497b9c683");
        try {
            IpV4Packet ipv4Packet =
                    IpV4Packet.newPacket(
                            ipUdpStunBindingRequest, 0, ipUdpStunBindingRequest.length);
            LOGGER.debug("Initializing STUN parsing and logging...");
            logPacket(ipv4Packet);
        } catch (IllegalRawDataException e) {
            LOGGER.warn(
                    "Failed to create/log dummy packet. Expect initial stun forwarding delay. ", e);
        }
    }
}
