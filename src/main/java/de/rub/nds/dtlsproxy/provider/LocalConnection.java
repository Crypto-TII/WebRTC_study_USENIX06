/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;

public class LocalConnection implements ConnectionInterface {

    private final ProxyConfiguration proxyConfiguration;

    private boolean filterActive = true;

    public LocalConnection(ProxyConfiguration proxyConfiguration) {
        this.proxyConfiguration = proxyConfiguration;
    }

    @Override
    public void initTransportHandlers(
            String clientToAttackerAlias, String attackerToServerAlias, State state) {

        ServerUdpTransportHandler serverHandler =
                new ServerUdpTransportHandler(
                        proxyConfiguration.getTimeout(), proxyConfiguration.getLocalServerPort());
        state.getTlsContext(clientToAttackerAlias).setTransportHandler(serverHandler);
        ClientUdpTransportHandler clientHandler =
                new ClientUdpTransportHandler(proxyConfiguration.getTimeout(), "localhost", 0);
        state.getTlsContext(attackerToServerAlias).setTransportHandler(clientHandler);
        state.getConfig().setWorkflowExecutorShouldOpen(true);
        state.getConfig().setWorkflowExecutorShouldClose(true);
    }

    @Override
    public boolean isInboundTheDtlsClient() {
        return true;
    }

    @Override
    public boolean isUsingTurn() {
        return false;
    }

    @Override
    public byte[] getTurnMappedConnectionIp() {
        return null;
    }

    @Override
    public Integer getTurnMappedConnectionPort() {
        return null;
    }

    @Override
    public FilterDirection getCreatedFromFilterDirection() {
        return FilterDirection.INBOUND;
    }

    @Override
    public void setFilterActive(boolean isFiltering) {
        this.filterActive = isFiltering;
    }

    @Override
    public boolean isFilterActive() {
        return filterActive;
    }
}
