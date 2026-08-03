/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp;

import de.rub.nds.dtlsproxy.probes.rtp.processing.Processor;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Given DTLS plaintext input from the server, this tries to complete a client-sided SCTP and RTCDC
 * handshake
 */
public class DataChannelCreationProcessor extends Processor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RtcChannel channel = new RtcChannel();

    @Override
    public void start() throws IOException {
        // kick off SCTP connection with INIT
        output(SctpUtil.getFreshInit());
        channel.setState(RtcChannelState.AWAIT_INIT_ACK);
    }

    @Override
    protected void process(byte[] sctpPacket) throws IOException {
        LOGGER.trace("Receiving data in state {}", channel.getState());

        switch (channel.getState()) {
            case INITIAL:
                throw new RuntimeException("Received SCTP before having started initiation");
            case AWAIT_INIT_ACK:
                processInitAck(sctpPacket);
                channel.setState(RtcChannelState.AWAIT_COOKIE_ACK);
                break;
            case AWAIT_COOKIE_ACK:
                sendChannelOpenRequest();
                channel.setState(RtcChannelState.POST_HANDSHAKE);

                processOnChannelSetup(sctpPacket);
                break;
            case POST_HANDSHAKE:
                if (!SctpUtil.containsData(sctpPacket)) {
                    // ignore ACKs
                    LOGGER.trace("Received ACK. Ignoring...");
                    break;
                }
                channel.incrementPacketsReceived();
                acknowledgeData(sctpPacket);

                // delegate to further processing
                processPostHandshake(sctpPacket);
                break;
            default:
                throw new RuntimeException(
                        "Received in illegal channel state: " + channel.getState().name());
        }
    }

    /**
     * Called upon completing the SCTP handshake
     *
     * @param sctpPacket raw sctp packet that completes the handshake
     */
    protected void processOnChannelSetup(byte[] sctpPacket) throws IOException {}

    /**
     * Called on receiving any DATA packet after the handshakes, including the Channel
     * acknowledgement
     *
     * @param sctpPacket raw sctp packet
     */
    protected void processPostHandshake(byte[] sctpPacket) throws IOException {}

    /** Extracts the cookie from the init ack given and sends a cookie ack back */
    private void processInitAck(byte[] sctpPacket) throws IOException {
        SctpUtil.extractCookie(sctpPacket, channel);
        SctpUtil.extractInitiateTag(sctpPacket, channel);
        byte[] cookieEcho = SctpUtil.createCookieEcho(channel);
        send(cookieEcho);
    }

    /** Sends a channel open request to the endpoint, which is expected after the sctp handshake */
    private void sendChannelOpenRequest() throws IOException {
        byte[] sctpPacket =
                SctpUtil.finalizeSctpPacket(SctpPacketLibrary.DATA_CHANNEL_OPEN_REQUEST, channel);
        send(sctpPacket);
    }

    /**
     * Scans an sctp packet for the sequence number in the data chunk and sends an acknowledgement
     * packet for it
     */
    private void acknowledgeData(byte[] sctpPacket) throws IOException {
        byte[] acknowledgement = SctpUtil.createDataAcknowledgment(sctpPacket, channel);
        send(acknowledgement);
    }

    protected void send(byte[] sctpPacket) throws IOException {
        output(sctpPacket);
    }

    public RtcChannel getChannel() {
        return channel;
    }
}
