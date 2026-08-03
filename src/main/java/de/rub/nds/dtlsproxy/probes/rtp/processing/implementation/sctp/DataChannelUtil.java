/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class DataChannelUtil {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Random RANDOM = new Random();

    private DataChannelUtil() {}

    /**
     * Extracts all values that are found in the json for the given keyword
     *
     * @param keyword keyword, must not contain any of ',' '}' ']'
     * @param json json string
     */
    public static List<String> extractValuesFromJson(String keyword, String json) {
        int nextIndex = json.indexOf(keyword, 0);
        List<String> values = new ArrayList<>();
        while (nextIndex != -1) {
            // sub one for "
            String value = extractValueFromJson(keyword, json, nextIndex - 1);
            values.add(value);
            nextIndex = json.indexOf(keyword, nextIndex + 1);
        }

        return values;
    }

    /**
     * Extract the first value that is found in the json for the given keyword
     *
     * @param keyword keyword, must not contain any of ',' '}' ']'
     * @param json json string
     */
    public static String extractValueFromJson(String keyword, String json) {
        return extractValueFromJson(keyword, json, 0);
    }

    /**
     * Extract the first value that is found in the json for the given keyword, starting at the
     * given position
     *
     * @param keyword keyword, must not contain any of ',' '}' ']'
     * @param json json string
     */
    public static String extractValueFromJson(String keyword, String json, int startPos) {
        String searchString = "\"" + keyword + "\":";
        int index = json.indexOf(searchString, startPos);

        // the value must not contain any of ',' '}' ']'

        if (index == -1) {
            LOGGER.trace(json);
            throw new RtcChannelException("Did not find keyword json: " + keyword);
        }

        int startIndex = index + searchString.length();
        int endIndex = startIndex + 1;
        while (endIndex < json.length() - 1) {
            char terminator = json.charAt(endIndex);
            if (terminator == ',' || terminator == '}' || terminator == ']') {
                break;
            }
            endIndex++;
        }

        return json.substring(startIndex, endIndex).trim();
    }

    /**
     * Creates an SSRC-like looking String. The result is a random unsigned int
     *
     * @return
     */
    public static String createUInt32String() {
        // creat random unsigned int, with msb always 1
        long ssrc = ((long) RANDOM.nextInt(Integer.MAX_VALUE)) << 1;
        ssrc += RANDOM.nextInt(2);
        return ssrc + "";
    }

    /**
     * extracts the first ssrc found in the sctp packet if there is any, otherwise an Exception is
     * thrown
     *
     * @param sctpPacket
     * @return
     */
    public static long extractFirstSsrc(byte[] sctpPacket) {
        String rtcChannelText = extractChannelText(sctpPacket);
        if (!rtcChannelText.contains("ssrc")) {
            throw new RtcChannelException("No SSRC found");
        }
        String ssrcValue = extractValueFromJson("ssrc", rtcChannelText);
        LOGGER.debug("Extracting SSRC from media request: {}", ssrcValue);
        return Long.parseLong(ssrcValue);
    }

    /**
     * Extracts the text payload of an sctp packet
     *
     * @param sctpPacket
     * @return
     */
    public static String extractChannelText(byte[] sctpPacket) {
        byte[] bytes = SctpUtil.extractDataPayload(sctpPacket);
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    /**
     * Crafts an SCTP packet for the given channel that carries the given data String. This
     * increments all SCTP sequence numbers of the channel
     *
     * @param data
     * @param channel
     * @return
     */
    public static byte[] createWebRtcStringDataPacket(String data, RtcChannel channel) {

        byte[] header =
                Arrays.copyOf(
                        SctpPacketLibrary.RTC_DATA_CHANNEL_SCTP_DATA_HEADER,
                        SctpPacketLibrary.RTC_DATA_CHANNEL_SCTP_DATA_HEADER.length);

        byte[] payload = data.getBytes(StandardCharsets.US_ASCII);

        ByteBuffer buffer = ByteBuffer.allocate(header.length + payload.length);
        buffer.put(header);
        buffer.position(header.length);
        buffer.put(payload);

        return SctpUtil.finalizeSctpPacket(buffer.array(), channel);
    }
}
