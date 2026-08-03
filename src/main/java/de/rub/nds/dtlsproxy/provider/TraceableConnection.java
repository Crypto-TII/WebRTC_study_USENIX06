/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.tlsattacker.core.state.State;

/** A caught DTLS connection including its TLS-Attacker State */
public class TraceableConnection {

    private State state;
    private ConnectionInterface connectionInterface;

    public TraceableConnection(State state, ConnectionInterface connectionInterface) {
        this.state = state;
        this.connectionInterface = connectionInterface;
    }

    public State getState() {
        return state;
    }

    public ConnectionInterface getConnectionInterface() {
        return connectionInterface;
    }
}
