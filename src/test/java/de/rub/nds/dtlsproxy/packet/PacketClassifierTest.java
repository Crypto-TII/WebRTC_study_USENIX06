/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.packet;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.utils.PacketLibrary;
import java.util.List;
import org.junit.jupiter.api.Test;

public class PacketClassifierTest {

    @Test
    public void testIsDtls() {
        assertTrue(ParserUtil.isDtls(PacketLibrary.CLIENT_HELLO_1));
        assertTrue(ParserUtil.isDtls(PacketLibrary.CLIENT_HELLO_2));
        assertTrue(ParserUtil.isDtls(PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS));
        assertTrue(ParserUtil.isDtls(PacketLibrary.ALERT_BAD_CERT));
        assertTrue(ParserUtil.isDtls(PacketLibrary.CLIENT_ENC_ALERT_5));
        assertTrue(ParserUtil.isDtls(PacketLibrary.SERVER_SESSION_TICKET_CCS_5));
        assertTrue(ParserUtil.isDtls(PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_4));
        assertTrue(ParserUtil.isDtls(PacketLibrary.DTLS_APP_DATA));
    }

    @Test
    public void testIsDtlsFalse() {
        assertFalse(ParserUtil.isDtls(PacketLibrary.STUN_REQUEST));
        assertFalse(ParserUtil.isDtls(PacketLibrary.STUN_SUCC_RESPONSE));
        assertFalse(ParserUtil.isDtls(PacketLibrary.DNS));
        assertFalse(ParserUtil.isDtls(PacketLibrary.RTP));
        assertFalse(ParserUtil.isDtls(PacketLibrary.RTCP_RECEIVER_REPORT));
        assertFalse(ParserUtil.isDtls(PacketLibrary.RTCP_SENDER_REPORT));
    }

    @Test
    public void testIsStun() {
        assertTrue(ParserUtil.isStun(PacketLibrary.STUN_REQUEST));
        assertTrue(ParserUtil.isStun(PacketLibrary.STUN_SUCC_RESPONSE));
    }

    @Test
    public void testIsStunFalse() {
        assertFalse(ParserUtil.isStun(PacketLibrary.CLIENT_HELLO_1));
        assertFalse(ParserUtil.isStun(PacketLibrary.CLIENT_HELLO_2));
        assertFalse(ParserUtil.isStun(PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS));
        assertFalse(ParserUtil.isStun(PacketLibrary.ALERT_BAD_CERT));
        assertFalse(ParserUtil.isStun(PacketLibrary.CLIENT_ENC_ALERT_5));
        assertFalse(ParserUtil.isStun(PacketLibrary.SERVER_SESSION_TICKET_CCS_5));
        assertFalse(ParserUtil.isStun(PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_4));
        assertFalse(ParserUtil.isStun(PacketLibrary.DTLS_APP_DATA));
        assertFalse(ParserUtil.isStun(PacketLibrary.DNS));
        assertFalse(ParserUtil.isStun(PacketLibrary.RTP));
        assertFalse(ParserUtil.isStun(PacketLibrary.RTCP_RECEIVER_REPORT));
        assertFalse(ParserUtil.isStun(PacketLibrary.RTCP_SENDER_REPORT));
        assertFalse(ParserUtil.isStun(PacketLibrary.SSDP));
    }

    @Test
    public void testIsTurn() {
        assertTrue(ParserUtil.isTurnChannelMessage(PacketLibrary.RTCP_ON_TURN_CHANNEL_MESSAGE));
        assertTrue(ParserUtil.isTurnChannelMessage(PacketLibrary.DTLS_HS_TURN_CHANNEL_MESSAGE));
    }

    @Test
    public void testIsRtp() {
        assertTrue(ParserUtil.isRtp(PacketLibrary.RTP));
    }

    @Test
    public void testIsRtpFalse() {
        assertFalse(ParserUtil.isRtp(PacketLibrary.STUN_REQUEST));
        assertFalse(ParserUtil.isRtp(PacketLibrary.STUN_SUCC_RESPONSE));
        assertFalse(ParserUtil.isRtp(PacketLibrary.CLIENT_HELLO_1));
        assertFalse(ParserUtil.isRtp(PacketLibrary.CLIENT_HELLO_2));
        assertFalse(ParserUtil.isRtp(PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS));
        assertFalse(ParserUtil.isRtp(PacketLibrary.ALERT_BAD_CERT));
        assertFalse(ParserUtil.isRtp(PacketLibrary.CLIENT_ENC_ALERT_5));
        assertFalse(ParserUtil.isRtp(PacketLibrary.SERVER_SESSION_TICKET_CCS_5));
        assertFalse(ParserUtil.isRtp(PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_4));
        assertFalse(ParserUtil.isRtp(PacketLibrary.DTLS_APP_DATA));
        assertFalse(ParserUtil.isRtp(PacketLibrary.DNS));
        assertFalse(ParserUtil.isRtp(PacketLibrary.RTCP_RECEIVER_REPORT));
        assertFalse(ParserUtil.isRtp(PacketLibrary.RTCP_SENDER_REPORT));
    }

    @Test
    public void testIsRtcp() {
        assertTrue(ParserUtil.isRtcp(PacketLibrary.RTCP_SENDER_REPORT));
        assertTrue(ParserUtil.isRtcp(PacketLibrary.RTCP_RECEIVER_REPORT));
    }

    @Test
    public void testIsRtcpFalse() {
        assertFalse(ParserUtil.isRtcp(PacketLibrary.STUN_REQUEST));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.STUN_SUCC_RESPONSE));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.CLIENT_HELLO_1));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.CLIENT_HELLO_2));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.SERVER_HELLO_WITH_CERTIFICATE_FRAGMENTS));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.ALERT_BAD_CERT));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.CLIENT_ENC_ALERT_5));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.SERVER_SESSION_TICKET_CCS_5));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.CLIENT_CERT_AND_KEY_EXCHANGE_4));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.DTLS_APP_DATA));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.DNS));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.RTP));
        assertFalse(ParserUtil.isRtcp(PacketLibrary.RTP_NO_EXTENTIONS));
    }

    @Test
    public void testClassifyLastLayer() {
        assertEquals(PacketType.RTP, ParserUtil.classifyLastLayer(PacketLibrary.RTP));
        assertEquals(PacketType.RTP, ParserUtil.classifyLastLayer(PacketLibrary.RTP_NO_EXTENTIONS));
        assertEquals(
                PacketType.RTCP, ParserUtil.classifyLastLayer(PacketLibrary.RTCP_SENDER_REPORT));
        assertEquals(PacketType.UNKNOWN, ParserUtil.classifyLastLayer(PacketLibrary.DNS));
        assertEquals(PacketType.UNKNOWN, ParserUtil.classifyLastLayer(PacketLibrary.SSDP));
        assertEquals(
                PacketType.STUN, ParserUtil.classifyLastLayer(PacketLibrary.STUN_SUCC_RESPONSE));
        assertEquals(
                PacketType.DTLS_APP_DATA,
                ParserUtil.classifyLastLayer(PacketLibrary.DTLS_APP_DATA));
        assertEquals(
                PacketType.DTLS_HANDSHAKE,
                ParserUtil.classifyLastLayer(PacketLibrary.CLIENT_HELLO_1));
        assertEquals(
                PacketType.DTLS_ALERT,
                ParserUtil.classifyLastLayer(PacketLibrary.CLIENT_ENC_ALERT_5));
        assertEquals(
                PacketType.DTLS_HANDSHAKE,
                ParserUtil.classifyLastLayer(PacketLibrary.DTLS_HS_ON_STUN_SEND_INDICATION));
        assertEquals(
                PacketType.RTCP,
                ParserUtil.classifyLastLayer(PacketLibrary.RTCP_ON_TURN_CHANNEL_MESSAGE));
        assertEquals(
                PacketType.DTLS_HANDSHAKE,
                ParserUtil.classifyLastLayer(PacketLibrary.DTLS_HS_TURN_CHANNEL_MESSAGE));
        assertEquals(
                PacketType.RTP,
                ParserUtil.classifyLastLayer(PacketLibrary.RTP_ON_TURN_CHANNEL_MESSAGE));
    }

    @Test
    public void testClassifyLayers() {
        assertArrayEquals(
                List.of(PacketType.STUN, PacketType.DTLS_HANDSHAKE).toArray(),
                ParserUtil.classifyLayers(PacketLibrary.DTLS_HS_ON_STUN_SEND_INDICATION).toArray());
        assertArrayEquals(
                List.of(PacketType.TURN_CHANNEL, PacketType.DTLS_HANDSHAKE).toArray(),
                ParserUtil.classifyLayers(PacketLibrary.DTLS_HS_TURN_CHANNEL_MESSAGE).toArray());
        assertArrayEquals(
                List.of(PacketType.TURN_CHANNEL, PacketType.RTP).toArray(),
                ParserUtil.classifyLayers(PacketLibrary.RTP_ON_TURN_CHANNEL_MESSAGE).toArray());
        assertArrayEquals(
                List.of(PacketType.TURN_CHANNEL, PacketType.RTCP).toArray(),
                ParserUtil.classifyLayers(PacketLibrary.RTCP_ON_TURN_CHANNEL_MESSAGE).toArray());
    }
}
