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
import de.rub.nds.dtlsproxy.probes.rtp.processing.SrtpPolicyFactory;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import jakarta.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.jitsi.srtp.SrtcpCryptoContext;
import org.jitsi.srtp.SrtpCryptoContext;
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.srtp.SrtpPolicy;
import org.jitsi.utils.ByteArrayBuffer;
import org.jitsi.utils.logging2.LoggerImpl;

public class SrtpHandler implements RtpCrypto {

    private static final Logger LOGGER = LogManager.getLogger();
    private final org.jitsi.utils.logging2.Logger rtpLogger = new LoggerImpl(getClass().getName());
    private final SrtpPolicy srtpPolicy;
    private final SrtpPolicy srtcpPolicy;
    private final SrtpCryptoContext srtpSendingContext;
    private final SrtpCryptoContext srtpReceivingContext;
    private final SrtcpCryptoContext srtcpSendingContext;
    private final SrtcpCryptoContext srtcpReceivingContext;

    public SrtpHandler(TlsContext context, boolean server) throws CryptoException {

        srtpPolicy = SrtpPolicyFactory.getRtpPolicy(context.getSelectedSrtpProtectionProfile());
        srtcpPolicy = SrtpPolicyFactory.getRtcpPolicy(context.getSelectedSrtpProtectionProfile());
        srtpPolicy.setSendReplayEnabled(true);
        srtcpPolicy.setSendReplayEnabled(true);
        srtpPolicy.setReceiveReplayEnabled(true);
        srtcpPolicy.setReceiveReplayEnabled(true);

        // attempt secret extraction from DTLS context
        byte[] keyMaterial =
                extractKeyMaterial(
                        context,
                        2 * (srtpPolicy.getEncKeyLength() + srtpPolicy.getSaltKeyLength()));

        byte[] client_write_SRTP_master_key;
        byte[] server_write_SRTP_master_key;
        byte[] server_write_SRTP_master_salt;
        byte[] client_write_SRTP_master_salt;

        try (ByteArrayInputStream keyMaterialStream = new ByteArrayInputStream(keyMaterial)) {

            // copy bytes as in https://www.rfc-editor.org/rfc/rfc5764
            client_write_SRTP_master_key =
                    keyMaterialStream.readNBytes(srtpPolicy.getEncKeyLength());
            server_write_SRTP_master_key =
                    keyMaterialStream.readNBytes(srtpPolicy.getEncKeyLength());
            client_write_SRTP_master_salt =
                    keyMaterialStream.readNBytes(srtpPolicy.getSaltKeyLength());
            server_write_SRTP_master_salt =
                    keyMaterialStream.readNBytes(srtpPolicy.getSaltKeyLength());

        } catch (IOException e) {
            LOGGER.error("Failed copying key material", e);
            throw new RuntimeException(e);
        }

        try {
            srtpSendingContext =
                    new SrtpCryptoContext(
                            true,
                            0x0,
                            0,
                            server ? server_write_SRTP_master_key : client_write_SRTP_master_key,
                            server ? server_write_SRTP_master_salt : client_write_SRTP_master_salt,
                            srtpPolicy,
                            rtpLogger);
            srtpReceivingContext =
                    new SrtpCryptoContext(
                            false,
                            0x0,
                            0,
                            server ? client_write_SRTP_master_key : server_write_SRTP_master_key,
                            server ? client_write_SRTP_master_salt : server_write_SRTP_master_salt,
                            srtpPolicy,
                            rtpLogger);
            srtcpSendingContext =
                    new SrtcpCryptoContext(
                            0x0,
                            server ? server_write_SRTP_master_key : client_write_SRTP_master_key,
                            server ? server_write_SRTP_master_salt : client_write_SRTP_master_salt,
                            srtcpPolicy,
                            rtpLogger);
            srtcpReceivingContext =
                    new SrtcpCryptoContext(
                            0x0,
                            server ? client_write_SRTP_master_key : server_write_SRTP_master_key,
                            server ? client_write_SRTP_master_salt : server_write_SRTP_master_salt,
                            srtcpPolicy,
                            rtpLogger);

        } catch (GeneralSecurityException e) {
            LOGGER.error("Error initializing RTP Attack crypto context: " + e);
            throw new RuntimeException(e);
        }

        LOGGER.trace(
                "Srtp handler (server={}) setup to use {}",
                server,
                context.getSelectedSrtpProtectionProfile().name());
    }

    /**
     * Attempts decryption of an SRTP packet in the Buffer
     *
     * @param srtpPacket Buffer with SRTP data, used for storing decrypted RTP aswell
     * @return SRTP decryption status result
     */
    @Override
    public SrtpErrorStatus decryptSrtp(ByteArrayBuffer srtpPacket) {

        try {
            // attempt decryption and return status object
            return srtpReceivingContext.reverseTransformPacket(srtpPacket, false);
        } catch (GeneralSecurityException e) {
            LOGGER.debug("SRTP decryption failed", e);
            return null; // return failure
        }
    }

    /**
     * Attempts encryption of an RTP packet in the Buffer
     *
     * @param rtpPacket Buffer with RTP data, used for storing encrypted SRTP aswell
     * @return Encryption SRTP status result
     */
    @Override
    public SrtpErrorStatus encryptSrtp(ByteArrayBuffer rtpPacket) {

        try {
            // attempt encryption and return status object
            return srtpSendingContext.transformPacket(rtpPacket);
        } catch (GeneralSecurityException e) {
            LOGGER.debug("SRTP encryption failed", e);
            return null; // return failure
        }
    }

    /**
     * Attempts decryption of an SRTCP packet in the Buffer
     *
     * @param srtcpPacket Buffer with SRTCP data, used for storing decrypted RTCP aswell
     * @return SRTCP decryption status result
     */
    @Override
    public SrtpErrorStatus decryptSrtcp(ByteArrayBuffer srtcpPacket) {

        try {
            // attempt decryption and return status object
            return srtcpReceivingContext.reverseTransformPacket(srtcpPacket);
        } catch (GeneralSecurityException e) {
            LOGGER.debug("SRTP decryption failed", e);
            return null; // return failure
        }
    }

    /**
     * Attempts encryption of an RTCP packet in the Buffer
     *
     * @param rtcpPacket Buffer with RTCP data, used for storing encrypted SRTCP aswell
     * @return Encryption SRTCP status result
     */
    @Override
    public SrtpErrorStatus encryptSrtcp(ByteArrayBuffer rtcpPacket) {

        try {
            // attempt encryption and return status object
            return srtcpSendingContext.transformPacket(rtcpPacket);
        } catch (GeneralSecurityException e) {
            LOGGER.debug("SRTP encryption failed", e);
            return null; // return failure
        }
    }

    public static byte[] extractKeyMaterial(TlsContext context, int len) throws CryptoException {

        LOGGER.trace(
                "Extracting SRTP key material for: prf {}, master secret {}, client random {}, server random {}",
                context.getPrfAlgorithm(),
                DatatypeConverter.printHexBinary(context.getMasterSecret()),
                DatatypeConverter.printHexBinary(context.getClientRandom()),
                DatatypeConverter.printHexBinary(context.getServerRandom()));

        return PseudoRandomFunction.compute(
                context.getPrfAlgorithm(),
                context.getMasterSecret(),
                "EXTRACTOR-dtls_srtp",
                Arrays.concatenate(context.getClientRandom(), context.getServerRandom()),
                len);
    }
}
