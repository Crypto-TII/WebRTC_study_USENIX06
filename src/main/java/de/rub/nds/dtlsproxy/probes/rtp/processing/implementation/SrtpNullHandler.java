/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import jakarta.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public class SrtpNullHandler implements RtpCrypto {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Will not perform any operations on the input data */
    @Override
    public SrtpErrorStatus decryptSrtp(ByteArrayBuffer srtpPacket) {
        // Do not process
        LOGGER.trace(
                "Null handling SRTP unprotect call with data {}",
                DatatypeConverter.printHexBinary(srtpPacket.getBuffer()));
        return SrtpErrorStatus.OK;
    }

    /** Will not perform any operations on the input data */
    @Override
    public SrtpErrorStatus encryptSrtp(ByteArrayBuffer rtpPacket) {
        // Do not process
        LOGGER.trace(
                "Null handling SRTP protect call with data {}",
                DatatypeConverter.printHexBinary(rtpPacket.getBuffer()));
        return SrtpErrorStatus.OK;
    }

    /** Will not perform any operations on the input data */
    @Override
    public SrtpErrorStatus decryptSrtcp(ByteArrayBuffer srtcpPacket) {
        // Do not process
        LOGGER.trace(
                "Null handling SRTCP unprotect call with data {}",
                DatatypeConverter.printHexBinary(srtcpPacket.getBuffer()));
        return SrtpErrorStatus.OK;
    }

    /** Will not perform any operations on the input data */
    @Override
    public SrtpErrorStatus encryptSrtcp(ByteArrayBuffer rtcpPacket) {
        // Do not process
        LOGGER.trace(
                "Null handling SRTCP protect call with data {}",
                DatatypeConverter.printHexBinary(rtcpPacket.getBuffer()));
        return SrtpErrorStatus.OK;
    }
}
