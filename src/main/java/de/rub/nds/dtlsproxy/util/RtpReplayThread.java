/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import jakarta.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RtpReplayThread extends Thread {

    private static final Logger LOGGER = LogManager.getLogger();

    private long[] timings;
    private byte[][] rtpPackets;

    private final long ssrc;
    private final ByteArrayWriteout udpTransportWriteout;

    public RtpReplayThread(String dumpFileName, ByteArrayWriteout udpTransportWriteout, long ssrc)
            throws IOException {
        super("RTP replay");
        this.udpTransportWriteout = udpTransportWriteout;
        this.ssrc = ssrc;
        loadFile(dumpFileName);
    }

    @Override
    public void run() {
        // Logic to replay RTP packets based on the timings and payloads arrays
        for (int i = 0; i < timings.length; i++) {
            long waitTime = (i == 0) ? 0 : timings[i] - timings[i - 1];
            try {
                Thread.sleep(waitTime);
            } catch (InterruptedException ignored) {
                break;
            }

            try {
                LOGGER.trace("replaying RTP {}", DatatypeConverter.printHexBinary(rtpPackets[i]));
                udpTransportWriteout.input(rtpPackets[i]);
            } catch (IOException e) {
                LOGGER.warn("Failed to send RTP replay");
                LOGGER.warn(e);
            }
        }
    }

    private void loadFile(String filename) throws IOException {

        File file = new File(filename);
        if (!file.exists()) {
            throw new IOException("Dump file not found: " + file.getAbsolutePath());
        }

        List<Long> timingsList = new ArrayList<>();
        List<byte[]> payloadsList = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            long firstTimestamp = -1;

            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\\|");

                // Parse timing
                long timing = Long.parseLong(parts[0]);

                // Set first timestamp to 0
                if (firstTimestamp == -1) {
                    firstTimestamp = timing;
                }

                timingsList.add(timing - firstTimestamp);

                // Parse rtpPayload (hex string to byte array)
                byte[] rtpPayload = DatatypeConverter.parseHexBinary(parts[1]);

                payloadsList.add(setSsrc(rtpPayload, ssrc));
            }
        }

        // Convert lists to arrays
        timings = new long[timingsList.size()];
        rtpPackets = new byte[payloadsList.size()][];

        for (int i = 0; i < timingsList.size(); i++) {
            timings[i] = timingsList.get(i);
            rtpPackets[i] = payloadsList.get(i);
        }
    }

    private static byte[] setSsrc(byte[] rtpPacket, long ssrc) {

        if (ssrc < 0 || ssrc > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("ssrc out of unsigned int bounds");
        }

        byte[] ssrcBytes = new byte[4];
        ssrcBytes[0] = (byte) (ssrc >> 24);
        ssrcBytes[1] = (byte) (ssrc >> 16);
        ssrcBytes[2] = (byte) (ssrc >> 8);
        ssrcBytes[3] = (byte) (ssrc);

        ByteBuffer buffer = ByteBuffer.wrap(rtpPacket);
        buffer.position(8);
        buffer.put(ssrcBytes);
        return buffer.array();
    }
}
