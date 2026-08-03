/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import java.io.IOException;

public class DumpingProcessor extends Processor {

    private final ByteArrayWriteout dataSink;

    public DumpingProcessor(ByteArrayWriteout dataSink) {
        this.dataSink = dataSink;
    }

    @Override
    protected void process(byte[] data) throws IOException {
        dataSink.input(data);
        output(data);
    }
}
