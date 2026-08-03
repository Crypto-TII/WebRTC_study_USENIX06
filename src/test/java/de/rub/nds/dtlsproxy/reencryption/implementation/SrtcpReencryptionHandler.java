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
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public class SrtcpReencryptionHandler extends ReencryptionHandler<RtpCrypto, ByteArrayBuffer> {

    private static final int BUFFER_SIZE = 2048;

    public SrtcpReencryptionHandler(
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
                MediaProtocol.RTCP,
                serverToClientPlaintextDumper,
                clientToServerPlaintextDumper,
                enableClientToAttackerEncryption,
                enableAttackerToServerEncryption);
    }

    @Override
    protected Thread createServerToClientThread() {
        return new Thread(
                createRunnable(
                        getConnection().getServerToClientRtcp(),
                        true,
                        getConnection().getAttackerToClientTransport()::sendData),
                "SRTCP serverToClient");
    }

    @Override
    protected Thread createClientToServerThread() {
        return new Thread(
                createRunnable(
                        getConnection().getClientToServerRtcp(),
                        false,
                        getConnection().getAttackerToServerTransport()::sendData),
                "SRTCP clientToServer");
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

        SrtpErrorStatus errDecrypt = cryptoContext.decryptSrtcp(ciphertext);

        if (errDecrypt != SrtpErrorStatus.OK)
            throw new RuntimeException(
                    "Failed " + getProtocol().name() + " decryption: " + errDecrypt.name());
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

        SrtpErrorStatus errEncrypt = cryptoContext.encryptSrtcp(plaintext);

        if (errEncrypt != SrtpErrorStatus.OK)
            throw new RuntimeException(
                    "Failed " + getProtocol().name() + " encryption: " + errEncrypt.name());

        return plaintext;
    }

    @Override
    protected byte[] intermediateToCipherBytes(ByteArrayBuffer intermediate) {
        byte[] array = new byte[intermediate.getLength()];
        System.arraycopy(intermediate.getBuffer(), 0, array, 0, intermediate.getLength());
        return array;
    }
}
