/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.DataChannelUtil;
import de.rub.nds.dtlsproxy.probes.rtp.processing.implementation.sctp.SctpUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** swaps out SSRC values found in sctp text messages for random ones */
public class JsonSsrcSwapProcessor extends Processor {

    protected static final Logger LOGGER = LogManager.getLogger();

    private static final int DATA_CHUNK_HEADER_LENGTH = 16;

    @Override
    protected void process(byte[] data) {

        // pre-scan for ssrc attribute
        String s = new String(data, StandardCharsets.US_ASCII);
        if (s.contains("\"ssrc\"")) {

            String payload = DataChannelUtil.extractChannelText(data);
            List<String> ssrcs = DataChannelUtil.extractValuesFromJson("ssrc", payload);
            for (String ssrc : ssrcs) {

                // create string of equal length, not to mess up the SCTP chunk
                String newSsrc = DataChannelUtil.createUInt32String();
                while (newSsrc.length() > ssrc.length()) {
                    newSsrc = newSsrc.substring(1);
                }

                LOGGER.trace("payload is '{}'", payload);
                LOGGER.trace("replacing ssrc {} with {}", ssrc, newSsrc);
                payload = payload.replaceAll(ssrc, newSsrc);
            }

            // overwrite last section of data
            byte[] newData = payload.getBytes(StandardCharsets.US_ASCII);
            int textDataStart = SctpUtil.getFirstDataChunkPosition(data) + DATA_CHUNK_HEADER_LENGTH;
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.position(textDataStart);
            buffer.put(newData);
            data = SctpUtil.updateChecksum(buffer.array());
        }

        try {
            output(data);
        } catch (IOException e) {
            LOGGER.warn("Failed to write forwarded data: {}\n", data, e);
        }
    }
}
