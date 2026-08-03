/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.Processor;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HexDumpingProcessor extends Processor {

    private static final Logger LOGGER = LogManager.getLogger();

    private FileWriter writer;

    public HexDumpingProcessor(String filename) {
        try {
            File file = new File(filename);
            if (!file.createNewFile()) {
                throw new IOException("can not create file " + file.getAbsolutePath());
            }
            writer = new FileWriter(file);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    @Override
    protected void process(byte[] data) throws IOException {
        writer.write(
                System.currentTimeMillis() + "|" + ArrayConverter.bytesToHexString(data) + "\n");
        writer.flush();
        output(data);
    }
}
