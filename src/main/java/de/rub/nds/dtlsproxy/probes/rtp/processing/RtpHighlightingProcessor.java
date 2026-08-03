/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Simple processor the logs the data as hex string with the 'Received and decrypted RTP media:'
 * prefix
 */
public class RtpHighlightingProcessor extends Processor {

    protected static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void process(byte[] data) throws IOException {
        LOGGER.info("Received and decrypted RTP media: {}", data);
        output(data);
    }
}
