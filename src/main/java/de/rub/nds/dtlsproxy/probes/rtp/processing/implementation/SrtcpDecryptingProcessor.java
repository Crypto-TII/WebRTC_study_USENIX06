/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.DecryptionProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import de.rub.nds.dtlsproxy.util.ByteArrayBufferImpl;
import java.util.List;
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public class SrtcpDecryptingProcessor extends DecryptionProcessor<RtpCrypto, ByteArrayBuffer> {

    public SrtcpDecryptingProcessor(RtpCrypto cryptoContext) {
        super(cryptoContext);
    }

    @Override
    protected ByteArrayBuffer decrypt(RtpCrypto cryptoContext, ByteArrayBuffer ciphertext) {

        SrtpErrorStatus errDecrypt = cryptoContext.decryptSrtcp(ciphertext);

        if (errDecrypt == SrtpErrorStatus.REPLAY_OLD || errDecrypt == SrtpErrorStatus.REPLAY_FAIL) {
            LOGGER.trace("encountered duplicate packet");
            return ciphertext;
        }

        if (errDecrypt != SrtpErrorStatus.OK) {
            throw new RuntimeException("Failed SRTCP decryption: " + errDecrypt.name());
        }
        return ciphertext;
    }

    @Override
    protected byte[] intermediateToPlainBytes(ByteArrayBuffer intermediate) {
        byte[] decrypted = new byte[intermediate.getLength()];
        System.arraycopy(
                intermediate.getBuffer(),
                0,
                decrypted,
                intermediate.getOffset(),
                intermediate.getLength());
        return decrypted;
    }

    @Override
    protected List<ByteArrayBuffer> parseToIntermediate(RtpCrypto cryptoContext, byte[] rawPacket) {
        int len = rawPacket.length;
        byte[] data_buffer = new byte[RtpCrypto.BUFFER_SIZE];
        System.arraycopy(rawPacket, 0, data_buffer, 0, len);
        return List.of(new ByteArrayBufferImpl(data_buffer, 0, len));
    }
}
