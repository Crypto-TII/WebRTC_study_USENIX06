/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.tlsattacker.core.state.State;

/**
 * Interface for Connections. Connections implementing this interface know how to setup the
 * transport handlers in a state.
 */
public interface ConnectionInterface {
    /**
     * Initializes the transport handlers in the state.
     *
     * @param clientToAttackerAlias The alias of the client to attacker connection
     * @param attackerToServerAlias The alias of the attacker to server connection
     * @param state The state to initialize the transport handlers in
     */
    public void initTransportHandlers(
            String clientToAttackerAlias, String attackerToServerAlias, State state);

    public boolean isInboundTheDtlsClient();

    public boolean isUsingTurn();

    public byte[] getTurnMappedConnectionIp();

    public Integer getTurnMappedConnectionPort();

    public FilterDirection getCreatedFromFilterDirection();

    public void setFilterActive(boolean isFiltering);

    public boolean isFilterActive();
}
