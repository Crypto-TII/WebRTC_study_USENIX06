/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import jakarta.xml.bind.DatatypeConverter;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ForwardProcessor extends Processor {

    protected static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void process(byte[] data) {
        try {
            output(data);
        } catch (IOException e) {
            LOGGER.warn(
                    "Failed to write forwarded data: {}\n",
                    DatatypeConverter.printHexBinary(data),
                    e);
        }
    }
}
