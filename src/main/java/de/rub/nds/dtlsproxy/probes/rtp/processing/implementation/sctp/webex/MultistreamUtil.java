/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.webex;

import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.DataChannelUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class MultistreamUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    private MultistreamUtil() {}

    public static String createMultistreamSourceAdvertisementAcknowledgment(String mediaRequest) {
        final String requestSqn = extractMultistreamSqn(mediaRequest) + "";
        final String mediaFamily = extractMultistreamMediaFamily(mediaRequest);
        final String mediaContent = extractMultistreamMediaContentType(mediaRequest);
        LOGGER.trace(
                "Creating Webex sourceAdvertisementAck with mediaFamily={}, mediaContent={}, sourceAdvertisementSeqNum={}",
                mediaFamily,
                mediaContent,
                requestSqn);

        String res = MultistreamMessageLibrary.SOURCE_ADVERTISEMENT_ACKNOWLEDGMENT_AUDIO_MAIN;
        res = res.replaceAll("XXACKSQNXX", requestSqn);
        res = res.replaceAll("AUDIO", mediaFamily);
        res = res.replaceAll("MAIN", mediaContent);
        LOGGER.trace("sourceAdvertisementAck created: {}", res);
        return res;
    }

    public static String createMultistreamMediaRequestAcknowledgment(String mediaRequest) {
        final String requestSqn = extractMultistreamSqn(mediaRequest) + "";
        final String mediaFamily = extractMultistreamMediaFamily(mediaRequest);
        final String mediaContent = extractMultistreamMediaContentType(mediaRequest);
        LOGGER.trace(
                "Creating Webex mediaRequestAck with mediaFamily={}, mediaContent={}, sourceAdvertisementSeqNum={}",
                mediaFamily,
                mediaContent,
                requestSqn);

        String res = MultistreamMessageLibrary.MEDIA_REQUEST_ACKNOWLEDGMENT_AUDIO_MAIN;
        res = res.replaceAll("XXACKSQNXX", requestSqn);
        res = res.replaceAll("AUDIO", mediaFamily);
        res = res.replaceAll("MAIN", mediaContent);
        LOGGER.trace("mediaRequestAck created: {}", res);
        return res;
    }

    public static boolean isMultistreamVideoSlidesSourceAdvertisement(byte[] sctpPacket) {
        String rtcChannelText = DataChannelUtil.extractChannelText(sctpPacket);
        return rtcChannelText.contains(
                "\"VIDEO\",\"mediaContent\":\"SLIDES\",\"payload\":{\"msgType\":\"sourceAdvertisement\"");
    }

    public static boolean isMultistreamAudioMediaRequest(byte[] sctpPacket) {
        String rtcChannelText = DataChannelUtil.extractChannelText(sctpPacket);
        return rtcChannelText.contains(
                "\"AUDIO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"mediaRequest\"");
    }

    public static boolean isMultistreamVideoMediaRequest(byte[] sctpPacket) {
        String rtcChannelText = DataChannelUtil.extractChannelText(sctpPacket);
        return rtcChannelText.contains(
                "\"VIDEO\",\"mediaContent\":\"MAIN\",\"payload\":{\"msgType\":\"mediaRequest\"");
    }

    public static boolean isMultistreamSourceAdvertisement(byte[] sctpPacket) {
        String rtcChannelText = DataChannelUtil.extractChannelText(sctpPacket);
        return rtcChannelText.contains("\"msgType\":\"sourceAdvertisement\"");
    }

    public static String extractMultistreamMediaContentType(String webexChannelText) {
        return DataChannelUtil.extractValueFromJson("mediaContent", webexChannelText);
    }

    public static String extractMultistreamMediaFamily(String webexChannelText) {
        return DataChannelUtil.extractValueFromJson("mediaFamily", webexChannelText);
    }

    public static int extractMultistreamSqn(String webexChannelText) {
        return Integer.parseInt(DataChannelUtil.extractValueFromJson("seqNum", webexChannelText));
    }
}
