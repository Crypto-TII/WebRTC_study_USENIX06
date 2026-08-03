/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp;

import jakarta.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.zip.CRC32C;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class SctpUtil {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Random RANDOM = new Random();

    private SctpUtil() {}

    /**
     * Extracts the data payload from the sctp packet, if no payload if found an exception is
     * thrown. It is assumed exactly one DATA chunk is contained
     *
     * @param sctpPacket
     * @return
     */
    public static byte[] extractDataPayload(byte[] sctpPacket) {
        int dataChunkPosition = getFirstDataChunkPosition(sctpPacket);
        if (dataChunkPosition == -1) {
            throw new RtcChannelException("Packet does not contain DATA");
        }
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        short chunkLength = buffer.getShort(dataChunkPosition + 2);
        if (chunkLength <= 16) {
            throw new RtcChannelException("Error parsing chunk length");
        }
        byte[] dataBytes = new byte[chunkLength - 16];
        buffer.position(16 + dataChunkPosition);
        buffer.get(dataBytes, 0, chunkLength - 16);
        return dataBytes;
    }

    /**
     * extracts the initiate tag from an init ack
     *
     * @param data
     * @param channel
     */
    public static void extractInitiateTag(byte[] data, RtcChannel channel) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte[] remoteInitiateTag = new byte[4];
        buffer.position(16);
        buffer.get(remoteInitiateTag, 0, 4);
        LOGGER.trace(
                "Extracted initiated tag (own verification tag) from remote init ack {}",
                DatatypeConverter.printHexBinary(remoteInitiateTag));
        channel.setVerificationTag(remoteInitiateTag);
    }

    /**
     * extracts the cookie from an init ack
     *
     * @param data
     * @param channel
     */
    public static void extractCookie(byte[] data, RtcChannel channel) {
        ByteBuffer buffer = ByteBuffer.wrap(data);

        int cookieParameterLength = buffer.getShort(34) & 0xFFFF;
        final int expectedRawCookieLength = 45;
        byte[] sctpCookie = new byte[expectedRawCookieLength];

        buffer.position(36);
        buffer.get(sctpCookie, 0, expectedRawCookieLength);

        LOGGER.debug(
                "extracted SCTP cookie of parameter length {}: {}",
                cookieParameterLength,
                DatatypeConverter.printHexBinary(sctpCookie));

        channel.setCookieLengthParameter(cookieParameterLength);
        channel.setCookie(sctpCookie);
    }

    /**
     * creates a cookie echo based on channel
     *
     * @param channel
     * @return
     */
    public static byte[] createCookieEcho(RtcChannel channel) {

        final byte[] cookie = channel.getCookie();
        final byte[] sampleEcho =
                Arrays.copyOf(SctpPacketLibrary.COOKIE_ECHO, SctpPacketLibrary.COOKIE_ECHO.length);

        ByteBuffer buffer = ByteBuffer.wrap(sampleEcho);
        final int originalCookieParameterLength = buffer.getShort(14);

        if (originalCookieParameterLength != channel.getCookieLengthParameter()) {
            throw new RtcChannelException(
                    "Cookie length does not fit to sample packet "
                            + channel.getCookieLengthParameter()
                            + " vs sample "
                            + originalCookieParameterLength);
        }

        LOGGER.trace(
                "Original cookie echo: {}",
                DatatypeConverter.printHexBinary(SctpPacketLibrary.COOKIE_ECHO));

        buffer.putShort(14, (short) channel.getCookieLengthParameter());
        buffer.position(16);
        buffer.put(cookie);

        byte[] cookieEcho = finalizeSctpPacket(buffer.array(), channel);

        LOGGER.trace("Modified cookie echo: {}", DatatypeConverter.printHexBinary(cookieEcho));

        return cookieEcho;
    }

    /**
     * creates an SCTP ACK for the given packet. It is assumed exactly one DATA chunk is contained
     *
     * @param sctpPacket
     * @param channel
     * @return
     */
    public static byte[] createDataAcknowledgment(byte[] sctpPacket, RtcChannel channel) {

        ByteBuffer buffer = ByteBuffer.wrap(SctpPacketLibrary.SACK);

        int sequenceNumber = extractSequenceNum(sctpPacket);
        LOGGER.trace("Creating acknowledgement for seq num {}", sequenceNumber);
        buffer.putInt(16, sequenceNumber);

        return finalizeSctpPacket(buffer.array(), channel);
    }

    /**
     * Extacts the STN from a given sctp packet
     *
     * @param sctpPacket
     * @return
     */
    public static int extractSequenceNum(byte[] sctpPacket) {
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);

        final int seqNumPos = 4;
        int position = getFirstDataChunkPosition(sctpPacket);

        int seqNum;

        if (position == -1) {
            throw new RtcChannelException("No data chunk found");
        }

        byte chunkType = (byte) (buffer.get(position) & 0x3F);
        if (chunkType == 0x00) {
            // found data chunk
            seqNum = buffer.getInt(position + seqNumPos);
        } else {
            throw new RtcChannelException(
                    "Failed to parse SCTP packet. Unknown chunk type: "
                            + DatatypeConverter.printHexBinary(new byte[] {chunkType}));
        }

        LOGGER.trace("Found sequence number {} at position {}", seqNum, position + seqNumPos);
        return seqNum;
    }

    /**
     * Searches for the first DATA chunk in an sctp packet. If none is found -1 is returned.
     *
     * @param sctpPacket
     * @return
     */
    public static int getFirstDataChunkPosition(byte[] sctpPacket) {
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);

        LOGGER.trace(
                "searching for data chunk in {}", DatatypeConverter.printHexBinary(sctpPacket));

        final int chunkStart = 12;
        int position = chunkStart;

        while (position < sctpPacket.length - 12) {
            byte chunkType = (byte) (buffer.get(position) & 0x3F);
            LOGGER.trace(
                    "Found chunk of type {} at {}",
                    DatatypeConverter.printHexBinary(new byte[] {chunkType}),
                    position);
            if (chunkType == 0x00) {
                return position;
            }

            short chunkLength = buffer.getShort(position + 2);
            position += chunkLength;
        }

        return -1;
    }

    /**
     * Checks if a DATA chunk can be found
     *
     * @param sctpPacket
     * @return
     */
    public static boolean containsData(byte[] sctpPacket) {
        return getFirstDataChunkPosition(sctpPacket) != -1;
    }

    /**
     * Crafts an INIT packets with a fresh init tag. Sets the initial TSN to all 0x00!
     *
     * @return
     */
    public static byte[] getFreshInit() {

        ByteBuffer buffer =
                ByteBuffer.wrap(
                        Arrays.copyOf(SctpPacketLibrary.INIT, SctpPacketLibrary.INIT.length));

        // set random initiate tag
        int initTag = RANDOM.nextInt();
        buffer.putInt(16, initTag);

        // set initial tsn to 0
        buffer.putInt(28, 0x00000000);

        LOGGER.trace("putting init tag {}", initTag);

        return updateChecksum(buffer.array());
    }

    /**
     * inserts the channel verification tag to an SCTP packet
     *
     * @param sctpPacket
     * @param channel
     * @return
     */
    public static byte[] insertVerificationTag(byte[] sctpPacket, RtcChannel channel) {
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        buffer.position(4);
        buffer.put(channel.getVerificationTag());
        return buffer.array();
    }

    /**
     * makes sure the DATA chunk present in the sctp packet is padded such that chunk length mod 4 =
     * 0, if one is present
     *
     * @param sctpPacket
     * @return
     */
    public static byte[] adjustDataChunkPadding(byte[] sctpPacket) {
        // TODO assumes only a single data chunk present
        int dataChunkPosition = getFirstDataChunkPosition(sctpPacket);
        if (dataChunkPosition == -1) {
            return sctpPacket; // no data chunk found
        }

        short chunkLength = (short) (sctpPacket.length - dataChunkPosition);

        if (chunkLength % 4 == 0) {
            // we good
            return sctpPacket;
        }

        byte[] paddingMissing = new byte[4 - (chunkLength % 4)];
        Arrays.fill(paddingMissing, (byte) 0x00);

        ByteBuffer buffer = ByteBuffer.allocate(sctpPacket.length + paddingMissing.length);
        buffer.put(sctpPacket);
        buffer.position(sctpPacket.length);
        buffer.put(paddingMissing);
        return buffer.array();
    }

    /**
     * Corrects the DATA chunk length field to match the actual data length, if one is present
     *
     * @param sctpPacket
     * @return
     */
    public static byte[] adjustDataChunkLength(byte[] sctpPacket) {
        // TODO assumes only a single data chunk present
        int dataChunkPosition = getFirstDataChunkPosition(sctpPacket);
        if (dataChunkPosition == -1) {
            return sctpPacket; // no data chunk found
        }

        short chunkLength = (short) (sctpPacket.length - dataChunkPosition);

        // count 0x00 bytes at the end of the data chunk and assume padding
        short paddingBytes = 0;
        for (int i = 0; i < sctpPacket.length - dataChunkPosition; i++) {
            if (sctpPacket[sctpPacket.length - i - 1] != 0x00) {
                break;
            }
            paddingBytes++;
        }

        chunkLength -= paddingBytes;

        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        buffer.putShort(dataChunkPosition + 2, chunkLength);
        return buffer.array();
    }

    /** Adjusts the TSN to the next TSN of the channel. Increments the TSN counter */
    public static byte[] adjustTransmissionSequenceNumber(byte[] sctpPacket, RtcChannel channel) {
        // TODO assumes only a single data chunk present
        int dataChunkPosition = getFirstDataChunkPosition(sctpPacket);
        if (dataChunkPosition == -1) {
            return sctpPacket; // no data chunk found
        }

        // data chunk present -> set tsn
        LOGGER.trace("Setting tsn of data chunk to {}", channel.getNextTsn());
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        buffer.putInt(dataChunkPosition + 4, channel.getNextTsn());
        channel.incrementTsn();
        return buffer.array();
    }

    /** Adjusts the SSN to the next SSN of the channel. Increments the SSN counter */
    public static byte[] adjustStreamSequenceNumber(byte[] sctpPacket, RtcChannel channel) {
        // TODO assumes only a single data chunk present
        int dataChunkPosition = getFirstDataChunkPosition(sctpPacket);
        if (dataChunkPosition == -1) {
            return sctpPacket; // no data chunk found
        }

        // data chunk present -> set ssn
        LOGGER.trace("Setting ssn of data chunk to {}", channel.getNextTsn());
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        buffer.putShort(dataChunkPosition + 10, channel.getNextSsn());
        channel.incrementSsn();
        return buffer.array();
    }

    /** Updates the checksum of the SCTP packet to validate correctly */
    public static byte[] updateChecksum(byte[] sctpPacket) {

        // Set the checksum field to zero (bytes 8 to 11)
        ByteBuffer buffer = ByteBuffer.wrap(sctpPacket);
        buffer.putInt(8, 0); // Zero out the checksum field

        // Calculate CRC32C checksum
        CRC32C crc32c = new CRC32C();
        crc32c.update(sctpPacket, 0, sctpPacket.length);
        long checksum = crc32c.getValue();

        // Inverse the byte order of the checksum
        int reversedChecksum = Integer.reverseBytes((int) checksum);

        // Insert the calculated checksum into the packet (bytes 8 to 11)
        buffer.putInt(8, reversedChecksum);

        LOGGER.trace("putting checksum {}", reversedChecksum);

        return buffer.array();
    }

    /**
     * Adjusts tags, sequence numbers, data padding, data chunk length if DATA is contained. If a
     * DATA chunk is present, no second DATA chunk may be present.
     *
     * @return
     */
    public static byte[] finalizeSctpPacket(byte[] sctpPacket, RtcChannel channel) {
        sctpPacket = adjustTransmissionSequenceNumber(sctpPacket, channel);
        sctpPacket = adjustStreamSequenceNumber(sctpPacket, channel);
        sctpPacket = insertVerificationTag(sctpPacket, channel);
        sctpPacket = adjustDataChunkPadding(sctpPacket);
        sctpPacket = adjustDataChunkLength(sctpPacket);
        sctpPacket = updateChecksum(sctpPacket);
        return sctpPacket;
    }
}
