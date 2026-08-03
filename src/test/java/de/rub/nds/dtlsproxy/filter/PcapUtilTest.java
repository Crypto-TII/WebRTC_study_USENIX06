/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.dtlsproxy.util.PcapUtil;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

public class PcapUtilTest {

    private static final String ETHER_IP_DTLS_SESSION_TICKET_CSS_FINISHED =
            "d85ed3addeea2c91ab875d2208004500025f1b6d40003a117a304216f394c0a8b29dc35ac8db024b5cf616fefd000000000000000e00f3040001c600050000000000e700001c2001c0a60c8e313adc6bcb1e40a251d4293edd67544bbe90af9f5a4a5f96ad33f2c7b71c88c3f5cfabc886d18dab2ff194194daa220b0c0215c510f37f5d92d3d1c84470ad4055374a092c11fde4e1a8d85010831d4c4cad65482b2ec48a4b57cb89515ff0c3d832cdd887e3c8376957e68ba4aa38146d571e7801b86e3f6a55265b1186e22b1c3dc62facc591709c7680496fc24a0a2f76b793aac873c666a3042eae5915b7325edb1a6852afdcd2168117fc2972d310cac26278d29679ed2e0288690473f82ae9ea78cb5199e53509fbcab3ffef53f185c3c710a025e1538266ca5f8f16fefd000000000000000f00eb040001c600050000e70000df1293ed8fcf245a2d697bd415520046b947a8ca9c49674cfe067037fc343527382c441cdf79b0cd5cf1a26aec025f226fe25840503307204db880817de3c8e5f6172a719ea9fd8331c75a16d872f6d3e40aae61cd3f21b48d983250beb8004456cd1792e02daa2d3b294fb043a3c25eb55530a2dc94914e5e83566e5321ca862bca3bcd4a72cdc5466c8829db3551f00667ddfdbf88d4d0242de2d50b9ab3c8573aa6d47984ae7d978e307260d3221ba248a12565c56f19e9c599847ed4750acb6417d1b79f2373ab788dd5804cf47bf61aacb03e06bb1a97bd1a5b732911fb14fefd000000000000001000010116fefd0001000000000000003097abbb5dd5c9c8894cb2df363e70d50176683ecaab86d8f95b6b64d7d0dba5af0177c9d597248585253b0089afedda30";

    @Test
    public void testSourceAddressCorrection() throws UnknownHostException, IllegalRawDataException {

        InetAddress srcAddr = Inet4Address.getByAddress(ByteArrays.parseByteArray("4216f394", ""));
        MacAddress srcMac = MacAddress.getByAddress(ByteArrays.parseByteArray("2c91ab875d22", ""));
        MacAddress dstMac = MacAddress.getByAddress(ByteArrays.parseByteArray("d85ed3addeea", ""));

        // Convert the hex string to a byte array.
        byte[] bytes = ByteArrays.parseByteArray(ETHER_IP_DTLS_SESSION_TICKET_CSS_FINISHED, "");

        // Create a Packet object from the byte array.
        Packet packetIn = EthernetPacket.newPacket(bytes, 0, bytes.length);
        Packet packetOut = PcapUtil.correctSourceAddress(packetIn, srcAddr, srcMac, dstMac);

        // check if packet unchanged by builder
        assertEquals(packetIn, packetOut);
    }

    @Test
    public void testDestinationAddressCorrection()
            throws UnknownHostException, IllegalRawDataException {

        InetAddress dstAddr = Inet4Address.getByAddress(ByteArrays.parseByteArray("c0a8b29d", ""));
        MacAddress srcMac = MacAddress.getByAddress(ByteArrays.parseByteArray("2c91ab875d22", ""));
        MacAddress dstMac = MacAddress.getByAddress(ByteArrays.parseByteArray("d85ed3addeea", ""));

        // Convert the hex string to a byte array.
        byte[] bytes = ByteArrays.parseByteArray(ETHER_IP_DTLS_SESSION_TICKET_CSS_FINISHED, "");

        // Create a Packet object from the byte array.
        Packet packetIn = EthernetPacket.newPacket(bytes, 0, bytes.length);
        Packet packetOut = PcapUtil.correctDestinationAddress(packetIn, dstAddr, dstMac, srcMac);

        // check if packet unchanged by builder
        assertEquals(packetIn, packetOut);
    }
}
