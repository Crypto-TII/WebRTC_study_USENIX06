/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.net.InetAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConnectionConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * In a call scenario with multiple DTLS handshakes taking place, which handshake is to be
     * caught
     */
    private int targetHandshakeNumber = 0;

    /** JA3 of a CH to be caught */
    private String targetClientHelloJA3;

    /** UDP local port of a CH to be caught */
    private int targetLocalPort;

    /** UDP remote port of a CH to be caught */
    private int targetRemotePort;

    /** IP Address of the remote service endpoint addressed in the CH */
    private String targetRemoteAddress;

    /** Wether to accept only connections that do NOT match the filter */
    private boolean invert = false;

    @SuppressWarnings("unused")
    public ConnectionConfig() {}

    public ConnectionConfig(
            int targetHandshakeNumber,
            String targetClientHelloJA3,
            int targetLocalPort,
            int targetRemotePort,
            String targetRemoteAddress,
            boolean invert) {
        this.targetHandshakeNumber = targetHandshakeNumber;
        this.targetClientHelloJA3 = targetClientHelloJA3;
        this.targetLocalPort = targetLocalPort;
        this.targetRemotePort = targetRemotePort;
        this.targetRemoteAddress = targetRemoteAddress;
        this.invert = invert;
    }

    public int getTargetHandshakeNumber() {
        return targetHandshakeNumber;
    }

    public void setTargetHandshakeNumber(int targetHandshakeNumber) {
        this.targetHandshakeNumber = targetHandshakeNumber;
    }

    public String getTargetClientHelloJA3() {
        return targetClientHelloJA3;
    }

    public void setTargetClientHelloJA3(String targetClientHelloJA3) {
        this.targetClientHelloJA3 = targetClientHelloJA3;
    }

    public int getTargetLocalPort() {
        return targetLocalPort;
    }

    public void setTargetLocalPort(int targetLocalPort) {
        this.targetLocalPort = targetLocalPort;
    }

    public int getTargetRemotePort() {
        return targetRemotePort;
    }

    public void setTargetRemotePort(int targetRemotePort) {
        this.targetRemotePort = targetRemotePort;
    }

    public String getTargetRemoteAddress() {
        return targetRemoteAddress;
    }

    public void setTargetRemoteAddress(String targetRemoteAddress) {
        this.targetRemoteAddress = targetRemoteAddress;
    }

    public boolean isInvert() {
        return invert;
    }

    public void setInvert(boolean invert) {
        this.invert = invert;
    }

    public boolean isValid() {
        if (targetHandshakeNumber < 0) {
            LOGGER.warn("invalid handshake number");
            return false;
        }
        if (targetLocalPort < 0) {
            LOGGER.warn("invalid local port");
            return false;
        }
        if (targetRemotePort < 0) {
            LOGGER.warn("invalid remote port");
            return false;
        }
        if (targetClientHelloJA3 != null && !targetClientHelloJA3.matches("^[0-9,-]+$")) {
            LOGGER.warn("invalid client hello JA3");
            return false;
        }
        try {
            InetAddress.getByName(targetRemoteAddress);
        } catch (Exception e) {
            LOGGER.warn("invalid remote ip addr");
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Handshake Nr: ");
        builder.append(targetHandshakeNumber == 0 ? "any" : targetHandshakeNumber);
        builder.append("\n");
        builder.append("Client Hello JA3: ");
        builder.append(targetClientHelloJA3 == null ? "any" : targetClientHelloJA3);
        builder.append("\n");
        builder.append("Local  Port: ");
        builder.append(targetLocalPort == 0 ? "any" : targetLocalPort);
        builder.append("\n");
        builder.append("Remote Port: ");
        builder.append(targetRemotePort == 0 ? "any" : targetRemotePort);
        builder.append("\n");
        builder.append("Remote Addr: ");
        builder.append(targetRemoteAddress == null ? "any" : targetRemoteAddress);
        builder.append("\n");
        builder.append("Invert Filter: ");
        builder.append(invert ? "yes" : "no");
        builder.append("\n");
        return builder.toString();
    }
}
