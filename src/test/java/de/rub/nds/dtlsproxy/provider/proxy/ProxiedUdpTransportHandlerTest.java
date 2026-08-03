/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider.proxy;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.transport.Connection;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.concurrent.ArrayBlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;

public class ProxiedUdpTransportHandlerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    public void testSendData() throws PcapNativeException, IOException {
        // Get all the network interfaces
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();

        // Iterate through all the network interfaces
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();
            LOGGER.debug(
                    "Checking interface {} IP {}",
                    networkInterface.getName(),
                    networkInterface.getInterfaceAddresses().get(0).getAddress().getHostAddress());
            sendDataFromInterface(networkInterface.getName());
        }
    }

    private void sendDataFromInterface(String interfaceName)
            throws PcapNativeException, IOException {
        PcapNetworkInterface networkInterface = Pcaps.getDevByName(interfaceName);
        int snapshotLength = 65536; // Maximum packet length to capture
        int timeout = 10; // Timeout in seconds
        PcapHandle handle =
                networkInterface.openLive(
                        snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
        Connection connection = new OutboundConnection("server", 4433, "1.2.3.4");
        connection.setTimeout(2000);
        connection.setUseIpv6(false);
        ProxiedUdpTransportHandler handler =
                new ProxiedUdpTransportHandler(
                        new ArrayBlockingQueue<>(10),
                        handle,
                        connection,
                        Inet4Address.getByName("10.181.84.232"),
                        Inet4Address.getByName("1.2.3.4"),
                        1234,
                        4321,
                        MacAddress.getByName("ac:1a:3d:f7:7a:23"),
                        MacAddress.getByName("00:1c:7f:82:06:14"));
        handler.sendData(new byte[16]);
        handle.close();
    }
}
