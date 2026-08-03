/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.reencryption.implementation;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.report.MediaReport;
import de.rub.nds.dtlsproxy.util.ByteArrayBufferImpl;
import de.rub.nds.dtlsproxy.util.MediaDumper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public class SrtpReencryptionHandler extends ReencryptionHandler<RtpCrypto, ByteArrayBuffer> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private static final int BUFFER_SIZE = 2048;

    public SrtpReencryptionHandler(
            RtpCrypto clientToAttackerCryptoContext,
            RtpCrypto attackerToServerCryptoContext,
            HookedConnection connection,
            long duration,
            MediaReport report,
            MediaDumper serverToClientPlaintextDumper,
            MediaDumper clientToServerPlaintextDumper,
            boolean enableClientToAttackerEncryption,
            boolean enableAttackerToServerEncryption) {
        super(
                clientToAttackerCryptoContext,
                attackerToServerCryptoContext,
                connection,
                duration,
                report,
                MediaProtocol.RTP,
                serverToClientPlaintextDumper,
                clientToServerPlaintextDumper,
                enableClientToAttackerEncryption,
                enableAttackerToServerEncryption);
    }

    @Override
    public Thread createServerToClientThread() {
        return new Thread(
                createRunnable(
                        getConnection().getServerToClientRtp(),
                        true,
                        getConnection().getAttackerToClientTransport()::sendData),
                "SRTP serverToClient");
    }

    @Override
    public Thread createClientToServerThread() {
        return new Thread(
                createRunnable(
                        getConnection().getClientToServerRtp(),
                        false,
                        getConnection().getAttackerToServerTransport()::sendData),
                "SRTP clientToServer");
    }

    @Override
    protected ByteArrayBuffer parseToIntermediate(RtpCrypto cryptoContext, byte[] rawPacket) {
        int len = rawPacket.length;
        byte[] data_buffer = new byte[BUFFER_SIZE];
        System.arraycopy(rawPacket, 0, data_buffer, 0, len);
        return new ByteArrayBufferImpl(data_buffer, 0, len);
    }

    @Override
    protected ByteArrayBuffer decrypt(RtpCrypto cryptoContext, ByteArrayBuffer ciphertext) {

        SrtpErrorStatus errDecrypt = cryptoContext.decryptSrtp(ciphertext);

        if (errDecrypt != SrtpErrorStatus.OK) {
            throw new RuntimeException(
                    "Failed " + getProtocol().name() + " decryption: " + errDecrypt.name());
        }
        return ciphertext;
    }

    @Override
    protected byte[] intermediateToPlainBytes(ByteArrayBuffer intermediate) {
        byte[] decrypted = new byte[intermediate.getLength()];
        System.arraycopy(intermediate.getBuffer(), 0, decrypted, 0, intermediate.getLength());
        return decrypted;
    }

    @Override
    protected ByteArrayBuffer encrypt(RtpCrypto cryptoContext, ByteArrayBuffer plaintext) {

        SrtpErrorStatus errEncrypt = cryptoContext.encryptSrtp(plaintext);

        if (errEncrypt != SrtpErrorStatus.OK) {
            throw new RuntimeException(
                    "Failed " + getProtocol().name() + " encryption: " + errEncrypt.name());
        }

        return plaintext;
    }

    @Override
    protected byte[] intermediateToCipherBytes(ByteArrayBuffer intermediate) {
        byte[] array = new byte[intermediate.getLength()];
        System.arraycopy(intermediate.getBuffer(), 0, array, 0, intermediate.getLength());
        return array;
    }
}
