/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils;

import static org.mockito.Mockito.*;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.provider.ProxiedConnectionProvider;
import de.rub.nds.dtlsproxy.provider.proxy.ConnectionEntry;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.provider.proxy.ProxiedUdpTransportHandler;
import de.rub.nds.dtlsproxy.utils.simulate.Simulation;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mockito.stubbing.Answer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.util.MacAddress;

/** Basic handler for connection mocking based on simulation streams. */
public class ProbeConnectionHandler {

    private static final ConnectionEntry DUMMY_ENTRY;

    private static final Logger LOGGER = LogManager.getLogger();

    static {
        try {
            DUMMY_ENTRY =
                    new ConnectionEntry(
                            Inet4Address.getByName("1.1.1.1"),
                            Inet4Address.getByName("1.1.1.2"),
                            Inet4Address.getByName("1.1.1.3"),
                            Inet4Address.getByName("1.1.1.4"),
                            666,
                            999,
                            MacAddress.getByName("AA:BB:CC:DD:EE:FF"),
                            MacAddress.getByName("AA:BB:CC:DD:EE:FF"),
                            MacAddress.getByName("AA:BB:CC:DD:EE:FF"),
                            MacAddress.getByName("AA:BB:CC:DD:EE:FF"));
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    // called for connection instantiation
    private final ProxiedConnectionProvider provider;

    // stores data send to client
    private final ConcurrentLinkedQueue<byte[]> sendToClient;

    // stores data send to server
    private final ConcurrentLinkedQueue<byte[]> sendToServer;

    public ProbeConnectionHandler(Simulation simulation, int timeout)
            throws IOException, NotOpenException, PcapNativeException {
        sendToClient = new ConcurrentLinkedQueue<>();
        sendToServer = new ConcurrentLinkedQueue<>();
        provider = mock(ProxiedConnectionProvider.class);
        ProxiedUdpTransportHandler attackerToClientSideHandler =
                mock(ProxiedUdpTransportHandler.class);
        ProxiedUdpTransportHandler attackerToServerSideHandler =
                mock(ProxiedUdpTransportHandler.class);

        // TODO data wrapping into pcap4j to be tested elsewhere

        // setup storing what is written to the connection by unit
        doAnswer(
                        (Answer<Void>)
                                invocation -> {
                                    sendToClient.add(invocation.getArgument(0));
                                    return null;
                                })
                .when(attackerToClientSideHandler)
                .sendData(any(byte[].class));
        doAnswer(
                        (Answer<Void>)
                                invocation -> {
                                    sendToServer.add(invocation.getArgument(0));
                                    return null;
                                })
                .when(attackerToServerSideHandler)
                .sendData(any(byte[].class));

        // setup simulated data written to connection by environment
        doAnswer((Answer<byte[]>) invocation -> simulation.getCurrentClientSource().fetchNext())
                .when(attackerToClientSideHandler)
                .fetchData();
        doAnswer((Answer<byte[]>) invocation -> simulation.getCurrentServerSource().fetchNext())
                .when(attackerToServerSideHandler)
                .fetchData();

        // created mocked connection on provider calls
        doAnswer(
                        inv -> {
                            HookedConnection hookedConnection =
                                    spy(
                                            new HookedConnection(
                                                    DUMMY_ENTRY,
                                                    timeout,
                                                    FilterDirection.OUTBOUND,
                                                    null,
                                                    null));
                            doAnswer(i -> attackerToClientSideHandler)
                                    .when(hookedConnection)
                                    .getAttackerToClientTransport();
                            doAnswer(i -> attackerToServerSideHandler)
                                    .when(hookedConnection)
                                    .getAttackerToServerTransport();
                            doAnswer(
                                            i -> {
                                                String clientToAttackerConnectionAlias =
                                                        i.getArgument(0);
                                                String attackerToServerConnectionAlias =
                                                        i.getArgument(1);
                                                State state = i.getArgument(2);
                                                state.getTlsContext(clientToAttackerConnectionAlias)
                                                        .setTransportHandler(
                                                                attackerToClientSideHandler);
                                                state.getTlsContext(attackerToServerConnectionAlias)
                                                        .setTransportHandler(
                                                                attackerToServerSideHandler);
                                                state.getConfig()
                                                        .setWorkflowExecutorShouldOpen(false);
                                                state.getConfig()
                                                        .setWorkflowExecutorShouldClose(false);
                                                return null;
                                            })
                                    .when(hookedConnection)
                                    .initTransportHandlers(
                                            any(String.class), any(String.class), any(State.class));
                            simulation.prepareNext();
                            return hookedConnection;
                        })
                .when(provider)
                .createConnection();
    }

    public ProxiedConnectionProvider getProvider() {
        return provider;
    }
}
