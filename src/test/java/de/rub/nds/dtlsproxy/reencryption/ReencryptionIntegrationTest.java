/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.probes.rtp.ReencryptProbe;
import de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass.BothBogusCertBypass;
import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.SrtpHandler;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.provider.proxy.ProxiedUdpTransportHandler;
import de.rub.nds.dtlsproxy.reencryption.implementation.LegacyReencryptProbe;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.ByteArrayBufferImpl;
import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ReencryptionIntegrationTest {

    private static final Logger LOGGER = LogManager.getLogger(ReencryptionIntegrationTest.class);

    private static final byte[] RTP_PACKET =
            DatatypeConverter.parseHexBinary(
                    "906F7EAE4204FD64EA4E0F63BEDE0001403010FF664507A4EB059B8ED97CB0D3652D829A5D9F9A75167E098B72D7FB9FBAE52B966A2C65E9137691AF59B95799EAA62577");
    private static final byte[] RTCP_PACKET =
            DatatypeConverter.parseHexBinary(
                    "81C90007D40C69DB243C5783000000000000541A0000011F5A224676000097D3");

    private static final int RTP_COUNT = 10;
    private static final int RTCP_COUNT = 10;

    private static final TlsContext DUMMY_CONTEXT;

    static {
        DUMMY_CONTEXT = new TlsContext(new Context(new State(), new OutboundConnection()));
        DUMMY_CONTEXT.setSelectedSrtpProtectionProfile(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);

        MockedStatic<SrtpHandler> mockedStaticSrtpHandler = Mockito.mockStatic(SrtpHandler.class);
        mockedStaticSrtpHandler
                .when(() -> SrtpHandler.extractKeyMaterial(any(TlsContext.class), anyInt()))
                .then(
                        invocationOnMock -> {
                            int len = invocationOnMock.getArgument(1);
                            byte[] res = new byte[len];
                            Arrays.fill(res, (byte) 0x01);
                            return res;
                        });

        Configurator.setLevel("de.rub.nds.dtlsproxy", Level.DEBUG);
    }

    @Test
    void testSrtpOutgoing() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(legacyInboundOutput, legacyOutboundOutput, RTP_COUNT, 0, 0, 0);
        ReencryptProbe newReencryption =
                mockNewProbing(newInboundOutput, newOutboundOutput, RTP_COUNT, 0, 0, 0);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (legacyInboundOutput.isEmpty());
        assert (newInboundOutput.isEmpty());
        assert (!legacyOutboundOutput.isEmpty());
        assert (!newOutboundOutput.isEmpty());

        assert (legacyOutboundOutput.size() == newOutboundOutput.size());
        for (int i = 0; i < legacyOutboundOutput.size(); i++) {
            assertArrayEquals(legacyOutboundOutput.get(i), newOutboundOutput.get(i));
        }
    }

    @Test
    void testSrtpIngoing() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(legacyInboundOutput, legacyOutboundOutput, 0, 0, RTP_COUNT, 0);
        ReencryptProbe newReencryption =
                mockNewProbing(newInboundOutput, newOutboundOutput, 0, 0, RTP_COUNT, 0);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (!legacyInboundOutput.isEmpty());
        assert (!newInboundOutput.isEmpty());
        assert (legacyOutboundOutput.isEmpty());
        assert (newOutboundOutput.isEmpty());

        assert (legacyInboundOutput.size() == newInboundOutput.size());
        for (int i = 0; i < legacyInboundOutput.size(); i++) {
            assertArrayEquals(legacyInboundOutput.get(i), newInboundOutput.get(i));
        }
    }

    @Test
    void testSrtcpOutgoing() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(legacyInboundOutput, legacyOutboundOutput, 0, RTCP_COUNT, 0, 0);
        ReencryptProbe newReencryption =
                mockNewProbing(newInboundOutput, newOutboundOutput, 0, RTCP_COUNT, 0, 0);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (legacyInboundOutput.isEmpty());
        assert (newInboundOutput.isEmpty());
        assert (!legacyOutboundOutput.isEmpty());
        assert (!newOutboundOutput.isEmpty());

        assert (legacyOutboundOutput.size() == newOutboundOutput.size());
        for (int i = 0; i < legacyOutboundOutput.size(); i++) {
            assertArrayEquals(legacyOutboundOutput.get(i), newOutboundOutput.get(i));
        }
    }

    @Test
    void testSrtcpIngoing() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(legacyInboundOutput, legacyOutboundOutput, 0, 0, 0, RTCP_COUNT);
        ReencryptProbe newReencryption =
                mockNewProbing(newInboundOutput, newOutboundOutput, 0, 0, 0, RTCP_COUNT);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (!legacyInboundOutput.isEmpty());
        assert (!newInboundOutput.isEmpty());
        assert (legacyOutboundOutput.isEmpty());
        assert (newOutboundOutput.isEmpty());

        assert (legacyInboundOutput.size() == newInboundOutput.size());
        for (int i = 0; i < legacyInboundOutput.size(); i++) {
            assertArrayEquals(legacyInboundOutput.get(i), newInboundOutput.get(i));
        }
    }

    @Test
    void testSrtpOutgoingNoEncryption() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(
                        legacyInboundOutput, legacyOutboundOutput, RTP_COUNT, 0, 0, 0, true, false);
        ReencryptProbe newReencryption =
                mockNewProbing(
                        newInboundOutput, newOutboundOutput, RTP_COUNT, 0, 0, 0, true, false);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (legacyInboundOutput.isEmpty());
        assert (newInboundOutput.isEmpty());
        assert (!legacyOutboundOutput.isEmpty());
        assert (!newOutboundOutput.isEmpty());

        assert (legacyOutboundOutput.size() == newOutboundOutput.size());
        for (int i = 0; i < legacyOutboundOutput.size(); i++) {
            assertArrayEquals(legacyOutboundOutput.get(i), newOutboundOutput.get(i));
        }
    }

    @Test
    void testSrtpIngoingNoEncryption() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(
                        legacyInboundOutput, legacyOutboundOutput, 0, 0, RTP_COUNT, 0, false, true);
        ReencryptProbe newReencryption =
                mockNewProbing(
                        newInboundOutput, newOutboundOutput, 0, 0, RTP_COUNT, 0, false, true);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (!legacyInboundOutput.isEmpty());
        assert (!newInboundOutput.isEmpty());
        assert (legacyOutboundOutput.isEmpty());
        assert (newOutboundOutput.isEmpty());

        assert (legacyInboundOutput.size() == newInboundOutput.size());
        for (int i = 0; i < legacyInboundOutput.size(); i++) {
            assertArrayEquals(legacyInboundOutput.get(i), newInboundOutput.get(i));
        }
    }

    @Test
    void testSrtcpOutgoingNoEncryption() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(
                        legacyInboundOutput,
                        legacyOutboundOutput,
                        0,
                        RTCP_COUNT,
                        0,
                        0,
                        true,
                        false);
        ReencryptProbe newReencryption =
                mockNewProbing(
                        newInboundOutput, newOutboundOutput, 0, RTCP_COUNT, 0, 0, true, false);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (legacyInboundOutput.isEmpty());
        assert (newInboundOutput.isEmpty());
        assert (!legacyOutboundOutput.isEmpty());
        assert (!newOutboundOutput.isEmpty());

        assert (legacyOutboundOutput.size() == newOutboundOutput.size());
        for (int i = 0; i < legacyOutboundOutput.size(); i++) {
            assertArrayEquals(legacyOutboundOutput.get(i), newOutboundOutput.get(i));
        }
    }

    @Test
    void testSrtcpIngoingNoEncryption() throws IOException {

        List<byte[]> legacyInboundOutput = new ArrayList<>();
        List<byte[]> legacyOutboundOutput = new ArrayList<>();
        List<byte[]> newInboundOutput = new ArrayList<>();
        List<byte[]> newOutboundOutput = new ArrayList<>();

        LegacyReencryptProbe legacyReencryption =
                mockLegacyProbing(
                        legacyInboundOutput,
                        legacyOutboundOutput,
                        0,
                        0,
                        0,
                        RTCP_COUNT,
                        false,
                        true);
        ReencryptProbe newReencryption =
                mockNewProbing(
                        newInboundOutput, newOutboundOutput, 0, 0, 0, RTCP_COUNT, false, true);

        legacyReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));
        newReencryption.test(new WebRtcPlatformReport("", FilterDirection.INBOUND));

        assert (!legacyInboundOutput.isEmpty());
        assert (!newInboundOutput.isEmpty());
        assert (legacyOutboundOutput.isEmpty());
        assert (newOutboundOutput.isEmpty());

        assert (legacyInboundOutput.size() == newInboundOutput.size());
        for (int i = 0; i < legacyInboundOutput.size(); i++) {
            assertArrayEquals(legacyInboundOutput.get(i), newInboundOutput.get(i));
        }
    }

    private LegacyReencryptProbe mockLegacyProbing(
            List<byte[]> inboundOutput,
            List<byte[]> outboundOutput,
            int rtpPacketsInbound,
            int rtcpPacketsInbound,
            int rtpPacketsOutbound,
            int rtcpPacketsOutbound)
            throws IOException {
        return mockLegacyProbing(
                inboundOutput,
                outboundOutput,
                rtpPacketsInbound,
                rtcpPacketsInbound,
                rtpPacketsOutbound,
                rtcpPacketsOutbound,
                true,
                true);
    }

    private LegacyReencryptProbe mockLegacyProbing(
            List<byte[]> inboundOutput,
            List<byte[]> outboundOutput,
            int rtpPacketsInbound,
            int rtcpPacketsInbound,
            int rtpPacketsOutbound,
            int rtcpPacketsOutbound,
            boolean encInbound,
            boolean encOutbound)
            throws IOException {

        ProxyConfiguration config = new ProxyConfiguration();
        config.setMediaProcessDuration(2000);

        ByteArrayWriteout inboundOutputVerbose =
                arr -> {
                    LOGGER.trace("writing to inbound: {}", DatatypeConverter.printHexBinary(arr));
                    inboundOutput.add(arr);
                };
        ByteArrayWriteout outboundOutputVerbose =
                arr -> {
                    LOGGER.trace("writing to outbound: {}", DatatypeConverter.printHexBinary(arr));
                    outboundOutput.add(arr);
                };
        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        config, new WebRtcPlatformReport("test", null), null, null);

        LegacyReencryptProbe probe =
                spy(
                        new LegacyReencryptProbe(
                                webrtcExecutionContext,
                                "LEGACY",
                                encInbound,
                                encInbound,
                                encInbound,
                                encOutbound,
                                encOutbound,
                                encOutbound) {
                            @Override
                            protected List<WebRtcProperties> getRequiredProperties() {
                                return List.of();
                            }
                        });

        // skip MitM Handshake, mock connection instead
        doAnswer(
                        invocationOnMock -> {
                            return new TraceableConnection(
                                    mock(State.class),
                                    mockConnection(
                                            inboundOutputVerbose,
                                            outboundOutputVerbose,
                                            rtpPacketsInbound,
                                            rtcpPacketsInbound,
                                            rtpPacketsOutbound,
                                            rtcpPacketsOutbound));
                        })
                .when(probe)
                .mitm(any(WebRtcPlatformReport.class));
        doAnswer(
                        invocationOnMock -> {
                            return mock(BothBogusCertBypass.class);
                        })
                .when(probe)
                .getAuthBypass();

        // init tls context
        when(probe.getClientToAttackerTlsContext()).thenReturn(DUMMY_CONTEXT);
        when(probe.getAttackerToServerTlsContext()).thenReturn(DUMMY_CONTEXT);

        // overwrite reporting
        doAnswer(
                        invocationOnMock -> {
                            return mock(MediaReport.class);
                        })
                .when(probe)
                .getMediaReport();

        return probe;
    }

    private ReencryptProbe mockNewProbing(
            List<byte[]> inboundOutput,
            List<byte[]> outboundOutput,
            int rtpPacketsInbound,
            int rtcpPacketsInbound,
            int rtpPacketsOutbound,
            int rtcpPacketsOutbound)
            throws IOException {
        return mockNewProbing(
                inboundOutput,
                outboundOutput,
                rtpPacketsInbound,
                rtcpPacketsInbound,
                rtpPacketsOutbound,
                rtcpPacketsOutbound,
                true,
                true);
    }

    private ReencryptProbe mockNewProbing(
            List<byte[]> inboundOutput,
            List<byte[]> outboundOutput,
            int rtpPacketsInbound,
            int rtcpPacketsInbound,
            int rtpPacketsOutbound,
            int rtcpPacketsOutbound,
            boolean encInbound,
            boolean encOutbound)
            throws IOException {
        ProxyConfiguration config = new ProxyConfiguration();
        config.setMediaProcessDuration(2000);
        ByteArrayWriteout inboundOutputVerbose =
                arr -> {
                    LOGGER.trace("writing to inbound: {}", DatatypeConverter.printHexBinary(arr));
                    inboundOutput.add(arr);
                };
        ByteArrayWriteout outboundOutputVerbose =
                arr -> {
                    LOGGER.trace("writing to outbound: {}", DatatypeConverter.printHexBinary(arr));
                    outboundOutput.add(arr);
                };

        WebrtcExecutionContext webrtcExecutionContext =
                new WebrtcExecutionContext(
                        new ProxyConfiguration(),
                        new WebRtcPlatformReport("null", null),
                        null,
                        null);

        ReencryptProbe probe =
                spy(
                        new ReencryptProbe(
                                webrtcExecutionContext,
                                "NEW",
                                encInbound,
                                encInbound,
                                encInbound,
                                encOutbound,
                                encOutbound,
                                encOutbound) {
                            @Override
                            protected List<WebRtcProperties> getRequiredProperties() {
                                return List.of();
                            }
                        });

        // skip MitM Handshake, mock connection instead
        doAnswer(
                        invocationOnMock -> {
                            return new TraceableConnection(
                                    mock(State.class),
                                    mockConnection(
                                            inboundOutputVerbose,
                                            outboundOutputVerbose,
                                            rtpPacketsInbound,
                                            rtcpPacketsInbound,
                                            rtpPacketsOutbound,
                                            rtcpPacketsOutbound));
                        })
                .when(probe)
                .mitm(any(WebRtcPlatformReport.class));
        doAnswer(
                        invocationOnMock -> {
                            return mock(BothBogusCertBypass.class);
                        })
                .when(probe)
                .getAuthBypass();

        // init tls context
        when(probe.getClientToAttackerTlsContext()).thenReturn(DUMMY_CONTEXT);
        when(probe.getAttackerToServerTlsContext()).thenReturn(DUMMY_CONTEXT);

        // overwrite reporting
        doAnswer(
                        invocationOnMock -> {
                            return mock(MediaReport.class);
                        })
                .when(probe)
                .getMediaReport();

        return probe;
    }

    private HookedConnection mockConnection(
            ByteArrayWriteout inboundOutput,
            ByteArrayWriteout outboundOutput,
            int rtpPacketsInbound,
            int rtcpPacketsInbound,
            int rtpPacketsOutbound,
            int rtcpPacketsOutbound)
            throws IOException, CryptoException {

        HookedConnection connection = mock(HookedConnection.class);

        ProxiedUdpTransportHandler inboundTransport = mock(ProxiedUdpTransportHandler.class);
        doAnswer(
                        invocationOnMock -> {
                            inboundOutput.input(invocationOnMock.getArgument(0));
                            return null;
                        })
                .when(inboundTransport)
                .sendData(any());

        ProxiedUdpTransportHandler outboundTransport = mock(ProxiedUdpTransportHandler.class);
        doAnswer(
                        invocationOnMock -> {
                            outboundOutput.input(invocationOnMock.getArgument(0));
                            return null;
                        })
                .when(outboundTransport)
                .sendData(any());

        doAnswer(
                        invocationOnMock -> {
                            return inboundTransport;
                        })
                .when(connection)
                .getAttackerToClientTransport();

        doAnswer(
                        invocationOnMock -> {
                            return outboundTransport;
                        })
                .when(connection)
                .getAttackerToServerTransport();

        final BlockingQueue<byte[]> inboundDtlsAppData = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> outboundDtlsAppData = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> inboundRtp = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> outboundRtp = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> inboundRtcp = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> outboundRtcp = new LinkedBlockingQueue<>();

        doAnswer(invocationOnMock -> inboundRtp).when(connection).getClientToServerRtp();
        doAnswer(invocationOnMock -> outboundRtp).when(connection).getServerToClientRtp();
        doAnswer(invocationOnMock -> inboundRtcp).when(connection).getClientToServerRtcp();
        doAnswer(invocationOnMock -> outboundRtcp).when(connection).getServerToClientRtcp();
        doAnswer(invocationOnMock -> inboundDtlsAppData)
                .when(connection)
                .getClientToServerDtlsAppData();
        doAnswer(invocationOnMock -> outboundDtlsAppData)
                .when(connection)
                .getServerToClientDtlsAppData();

        // populate queues
        populateSrtp(inboundRtp, rtpPacketsInbound);
        populateSrtcp(inboundRtcp, rtcpPacketsInbound);
        populateSrtp(outboundRtp, rtpPacketsOutbound);
        populateSrtcp(outboundRtcp, rtcpPacketsOutbound);

        return connection;
    }

    private static TlsContext mockContext() {

        TlsContext mocked = mock(TlsContext.class);

        doAnswer(
                        invocationOnMock -> {
                            return SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80;
                        })
                .when(mocked)
                .getSelectedSrtpProtectionProfile();

        return mocked;
    }

    private static RtpCrypto mockRtpCrypto(boolean server) throws CryptoException {
        return new SrtpHandler(mockContext(), server);
    }

    private void populateSrtp(BlockingQueue<byte[]> queue, int packetCount) throws CryptoException {

        RtpCrypto crypto = mockRtpCrypto(false);

        for (int i = 0; i < packetCount; i++) {

            byte[] rtpPacket = Arrays.copyOf(RTP_PACKET, RTP_PACKET.length);
            rtpPacket[2] = (byte) (i / 255);
            rtpPacket[3] = (byte) (i % 256);

            byte[] dataBuffer = new byte[RtpCrypto.BUFFER_SIZE];
            System.arraycopy(rtpPacket, 0, dataBuffer, 0, rtpPacket.length);
            ByteArrayBufferImpl buffer = new ByteArrayBufferImpl(dataBuffer, 0, rtpPacket.length);
            crypto.encryptSrtp(buffer);

            byte[] bufferOut = new byte[buffer.getLength()];
            System.arraycopy(
                    buffer.getBuffer(), 0, bufferOut, buffer.getOffset(), buffer.getLength());

            LOGGER.debug(
                    "queueing SRTP encrypted: {}", DatatypeConverter.printHexBinary(bufferOut));
            queue.add(bufferOut);
        }
    }

    private void populateSrtcp(BlockingQueue<byte[]> queue, int packetCount)
            throws CryptoException {

        RtpCrypto crypto = mockRtpCrypto(false);

        for (int i = 0; i < packetCount; i++) {
            byte[] rtcpPacket = Arrays.copyOf(RTCP_PACKET, RTCP_PACKET.length);

            byte[] dataBuffer = new byte[RtpCrypto.BUFFER_SIZE];
            System.arraycopy(rtcpPacket, 0, dataBuffer, 0, rtcpPacket.length);
            ByteArrayBufferImpl buffer = new ByteArrayBufferImpl(dataBuffer, 0, rtcpPacket.length);
            crypto.encryptSrtcp(buffer);

            byte[] bufferOut = new byte[buffer.getLength()];
            System.arraycopy(
                    buffer.getBuffer(), 0, bufferOut, buffer.getOffset(), buffer.getLength());

            LOGGER.debug(
                    "queueing SRTCP encrypted: {}", DatatypeConverter.printHexBinary(bufferOut));

            queue.add(bufferOut);
        }
    }
}
