/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.util.ArchivingBlockingQueue;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.PcapHandle;

public class HookedConnection implements ConnectionInterface {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
     * Queues for packets received and to be processed by the tool
     */
    private final ArchivingBlockingQueue<byte[]> inboundDtlsHandshake =
            new ArchivingBlockingQueue<>();
    private final ArchivingBlockingQueue<byte[]> outboundDtlsHandshake =
            new ArchivingBlockingQueue<>();
    private final BlockingQueue<byte[]> inboundDtlsAppData = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> outboundDtlsAppData = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> inboundRtp = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> outboundRtp = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> inboundRtcp = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> outboundRtcp = new LinkedBlockingQueue<>();

    private ProxiedUdpTransportHandler attackerToServerTransport;
    private ProxiedUdpTransportHandler attackerToClientTransport;

    private final ConnectionEntry entry;

    private boolean isUsingTurn = false;
    private byte[] turnMappedConnectionIp = null;
    private Integer turnMappedConnectionPort = null;

    private boolean filterActive = true;

    private final int timeout;

    private final FilterDirection createdFromFilterDirection;

    private final HashMap<PacketType, Integer> packetCountsInbound =
            new HashMap<PacketType, Integer>();
    private final HashMap<PacketType, Integer> packetCountsOutbound =
            new HashMap<PacketType, Integer>();

    private PcapHandle inboundHandle;
    private PcapHandle outboundHandle;

    public HookedConnection(
            ConnectionEntry entry,
            int timeout,
            FilterDirection createdFromFilterDirection,
            PcapHandle inboundHandle,
            PcapHandle outboundHandle) {
        this.entry = entry;
        this.timeout = timeout;
        this.createdFromFilterDirection = createdFromFilterDirection;
        this.inboundHandle = inboundHandle;
        this.outboundHandle = outboundHandle;
    }

    public synchronized void setFilterActive(boolean isFiltering) {
        this.filterActive = isFiltering;
    }

    public synchronized boolean isFilterActive() {
        return filterActive;
    }

    public byte[] getTurnMappedConnectionIp() {
        return turnMappedConnectionIp;
    }

    public void setTurnMappedConnectionIp(byte[] turnMappedConnectionIp) {
        this.turnMappedConnectionIp = turnMappedConnectionIp;
    }

    public Integer getTurnMappedConnectionPort() {
        return turnMappedConnectionPort;
    }

    public void setTurnMappedConnectionPort(Integer turnMappedConnectionPort) {
        this.turnMappedConnectionPort = turnMappedConnectionPort;
    }

    public boolean isUsingTurn() {
        return isUsingTurn;
    }

    public void setUsingTurn(boolean isUsingTurn) {
        this.isUsingTurn = isUsingTurn;
    }

    @Override
    public FilterDirection getCreatedFromFilterDirection() {
        return createdFromFilterDirection;
    }

    public ArchivingBlockingQueue<byte[]> getInboundDtlsHandshake() {
        return inboundDtlsHandshake;
    }

    public ArchivingBlockingQueue<byte[]> getOutboundDtlsHandshake() {
        return outboundDtlsHandshake;
    }

    protected BlockingQueue<byte[]> getInboundDtlsAppData() {
        return inboundDtlsAppData;
    }

    protected BlockingQueue<byte[]> getOutboundDtlsAppData() {
        return outboundDtlsAppData;
    }

    protected BlockingQueue<byte[]> getInboundRtp() {
        return inboundRtp;
    }

    protected BlockingQueue<byte[]> getOutboundRtp() {
        return outboundRtp;
    }

    protected BlockingQueue<byte[]> getInboundRtcp() {
        return inboundRtcp;
    }

    protected BlockingQueue<byte[]> getOutboundRtcp() {
        return outboundRtcp;
    }

    public ConnectionEntry getEntry() {
        return entry;
    }

    @Override
    public void initTransportHandlers(
            String clientToAttackerConnectionAlias,
            String attackerToServerConnectionAlias,
            State state) {
        LOGGER.debug("Initializing transport handlers in state");

        OutboundConnection outboundConnection;
        InboundConnection inboundConnection;
        if (createdFromFilterDirection.equals(FilterDirection.INBOUND)) {
            outboundConnection = new OutboundConnection(attackerToServerConnectionAlias);
            inboundConnection = new InboundConnection(clientToAttackerConnectionAlias);
            inboundConnection.setTimeout(getTimeout());
            outboundConnection.setTimeout(getTimeout());
            inboundConnection.setUseIpv6(false);
            outboundConnection.setUseIpv6(false);
            attackerToClientTransport =
                    new ProxiedUdpTransportHandler(
                            inboundDtlsHandshake,
                            inboundHandle,
                            inboundConnection,
                            entry.getOutboundTargetIp(),
                            entry.getInboundTargetIp(),
                            entry.getRemotePort(),
                            entry.getLocalPort(),
                            entry.getInboundSourceMacAddress(),
                            entry.getInboundDestinationMacAddress());
            attackerToServerTransport =
                    new ProxiedUdpTransportHandler(
                            outboundDtlsHandshake,
                            outboundHandle,
                            outboundConnection,
                            entry.getOutboundIp(),
                            entry.getOutboundTargetIp(),
                            entry.getLocalPort(),
                            entry.getRemotePort(),
                            entry.getOutboundSourceMacAddress(),
                            entry.getOutboundDestinationMacAddress());
        } else {
            outboundConnection = new OutboundConnection(clientToAttackerConnectionAlias);
            inboundConnection = new InboundConnection(attackerToServerConnectionAlias);
            inboundConnection.setTimeout(getTimeout());
            outboundConnection.setTimeout(getTimeout());
            inboundConnection.setUseIpv6(false);
            outboundConnection.setUseIpv6(false);
            attackerToServerTransport =
                    new ProxiedUdpTransportHandler(
                            inboundDtlsHandshake,
                            inboundHandle,
                            inboundConnection,
                            entry.getOutboundTargetIp(),
                            entry.getInboundTargetIp(),
                            entry.getRemotePort(),
                            entry.getLocalPort(),
                            entry.getInboundSourceMacAddress(),
                            entry.getInboundDestinationMacAddress());
            attackerToClientTransport =
                    new ProxiedUdpTransportHandler(
                            outboundDtlsHandshake,
                            outboundHandle,
                            outboundConnection,
                            entry.getOutboundIp(),
                            entry.getOutboundTargetIp(),
                            entry.getLocalPort(),
                            entry.getRemotePort(),
                            entry.getOutboundSourceMacAddress(),
                            entry.getOutboundDestinationMacAddress());
        }
        state.getTlsContext(clientToAttackerConnectionAlias)
                .setTransportHandler(attackerToClientTransport);
        state.getTlsContext(attackerToServerConnectionAlias)
                .setTransportHandler(attackerToServerTransport);
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        state.getConfig().setWorkflowExecutorShouldClose(false);
    }

    public int getTimeout() {
        return timeout;
    }

    @Override
    public boolean isInboundTheDtlsClient() {
        if (createdFromFilterDirection.equals(FilterDirection.INBOUND)) {
            return true;
        } else {
            return false;
        }
    }

    public void updatePacketCount(List<PacketType> layers, FilterDirection filterDirection) {
        if (filterDirection.equals(FilterDirection.INBOUND)) {
            for (PacketType type : layers) {
                packetCountsInbound.putIfAbsent(type, 0);
                packetCountsInbound.put(type, packetCountsInbound.get(type) + 1);
            }
        } else {
            for (PacketType type : layers) {
                packetCountsOutbound.putIfAbsent(type, 0);
                packetCountsOutbound.put(type, packetCountsOutbound.get(type) + 1);
            }
        }
    }

    public HashMap<PacketType, Integer> getPacketCountsInbound() {
        return packetCountsInbound;
    }

    public HashMap<PacketType, Integer> getPacketCountsOutbound() {
        return packetCountsOutbound;
    }

    public BlockingQueue<byte[]> getClientToServerDtlsAppData() {
        if (isInboundTheDtlsClient()) {
            return inboundDtlsAppData;
        } else {
            return outboundDtlsAppData;
        }
    }

    public BlockingQueue<byte[]> getServerToClientDtlsAppData() {
        if (isInboundTheDtlsClient()) {
            return outboundDtlsAppData;
        } else {
            return inboundDtlsAppData;
        }
    }

    public BlockingQueue<byte[]> getClientToServerRtp() {
        if (isInboundTheDtlsClient()) {
            return inboundRtp;
        } else {
            return outboundRtp;
        }
    }

    public BlockingQueue<byte[]> getServerToClientRtp() {
        if (isInboundTheDtlsClient()) {
            return outboundRtp;
        } else {
            return inboundRtp;
        }
    }

    public BlockingQueue<byte[]> getClientToServerRtcp() {
        if (isInboundTheDtlsClient()) {
            return inboundRtcp;
        } else {
            return outboundRtcp;
        }
    }

    public BlockingQueue<byte[]> getServerToClientRtcp() {
        if (isInboundTheDtlsClient()) {
            return outboundRtcp;
        } else {
            return inboundRtcp;
        }
    }

    public ProxiedUdpTransportHandler getAttackerToClientTransport() {
        return attackerToClientTransport;
    }

    public void setAttackerToClientTransport(ProxiedUdpTransportHandler attackerToClientTransport) {
        this.attackerToClientTransport = attackerToClientTransport;
    }

    public ProxiedUdpTransportHandler getAttackerToServerTransport() {
        return attackerToServerTransport;
    }

    public void setAttackerToServerTransport(ProxiedUdpTransportHandler attackerToServerTransport) {
        this.attackerToServerTransport = attackerToServerTransport;
    }

    @Override
    public String toString() {

        String localAddr = entry.getInboundTargetIp().getHostAddress() + ":" + entry.getLocalPort();
        String remoteAddr =
                entry.getOutboundTargetIp().getHostAddress() + ":" + entry.getRemotePort();
        String direction =
                this.createdFromFilterDirection == FilterDirection.INBOUND ? " -> " : " <- ";
        String turnEnabled = isUsingTurn ? " on TURN" : "";

        return localAddr + direction + remoteAddr + turnEnabled;
    }
}
