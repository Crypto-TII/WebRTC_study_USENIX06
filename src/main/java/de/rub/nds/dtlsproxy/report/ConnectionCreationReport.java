/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.report;

import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ConnectionCreationReport {

    private List<ConnectionInterface> connections;

    public ConnectionCreationReport() {
        connections = new LinkedList<>();
    }

    public void addConnection(ConnectionInterface connection) {
        connections.add(connection);
    }

    public int getNumberOfConnections() {
        return connections.size();
    }

    public int getNumberOfPlainConnections() {
        int count = 0;
        for (ConnectionInterface connection : connections) {
            if (!connection.isUsingTurn()) {
                count++;
            }
        }
        return count;
    }

    public int getNumberOfTurnConnections() {
        int count = 0;
        for (ConnectionInterface connection : connections) {
            if (connection.isUsingTurn()) {
                count++;
            }
        }
        return count;
    }

    public int getNumberOfInboundClientConnections() {
        int count = 0;
        for (ConnectionInterface connection : connections) {
            if (connection.isInboundTheDtlsClient()) {
                count++;
            }
        }
        return count;
    }

    public int getNumberOfInboundServerConnections() {
        int count = 0;
        for (ConnectionInterface connection : connections) {
            if (!connection.isInboundTheDtlsClient()) {
                count++;
            }
        }
        return count;
    }

    public int getNumberOfDifferentLocalPorts() {
        Set<Integer> ports = new HashSet<>();
        for (ConnectionInterface connection : connections) {
            if (connection instanceof HookedConnection) {
                HookedConnection hookedConnection = (HookedConnection) connection;
                ports.add(hookedConnection.getEntry().getLocalPort());
            }
        }
        return ports.size();
    }

    public int getNumberOfDifferentRemotePorts() {
        Set<Integer> ports = new HashSet<>();
        for (ConnectionInterface connection : connections) {
            if (connection instanceof HookedConnection) {
                HookedConnection hookedConnection = (HookedConnection) connection;
                ports.add(hookedConnection.getEntry().getRemotePort());
            }
        }
        return ports.size();
    }

    public int getNumberOfDifferentTurnMappedPorts() {
        Set<Integer> ports = new HashSet<>();
        for (ConnectionInterface connection : connections) {
            if (connection.getTurnMappedConnectionPort() != null) {
                ports.add(connection.getTurnMappedConnectionPort());
            }
        }
        return ports.size();
    }

    public int getNumberOfDifferentTurnMappedAddresses() {
        Set<String> addressSet = new HashSet<>();
        for (ConnectionInterface connection : connections) {
            if (connection.getTurnMappedConnectionPort() != null) {
                addressSet.add(
                        ArrayConverter.bytesToHexString(connection.getTurnMappedConnectionIp()));
            }
        }
        return addressSet.size();
    }

    public int getNumberOfTotalTurnMappedConnections() {
        int count = 0;
        for (ConnectionInterface connection : connections) {
            if (connection.getTurnMappedConnectionPort() != null) {
                count++;
            }
        }
        return count;
    }
}
