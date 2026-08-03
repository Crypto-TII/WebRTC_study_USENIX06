/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import java.io.IOException;
import java.io.InputStream;

public class ReadOnlyTransportHandler extends UdpTransportHandler {

    private InputStream inputStream;

    public ReadOnlyTransportHandler(ConnectionEndType type, InputStream inputStream) {
        super(0, type);
        this.inputStream = inputStream;
    }

    @Override
    public byte[] fetchData() throws IOException {
        return inputStream.readAllBytes();
    }

    @Override
    public byte[] fetchData(int amountOfData) throws IOException {
        return inputStream.readNBytes(amountOfData);
    }

    @Override
    public void closeClientConnection() throws IOException {}

    @Override
    public void preInitialize() throws IOException {}

    @Override
    public void initialize() throws IOException {}
}
