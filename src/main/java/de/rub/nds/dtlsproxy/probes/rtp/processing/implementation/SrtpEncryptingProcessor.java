/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing.implementation;

import de.rub.nds.dtlsproxy.probes.rtp.processing.EncryptionProcessor;
import de.rub.nds.dtlsproxy.probes.rtp.processing.RtpCrypto;
import de.rub.nds.dtlsproxy.util.ByteArrayBufferImpl;
import java.util.List;
import org.jitsi.srtp.SrtpErrorStatus;
import org.jitsi.utils.ByteArrayBuffer;

public class SrtpEncryptingProcessor extends EncryptionProcessor<RtpCrypto, ByteArrayBuffer> {

    public SrtpEncryptingProcessor(RtpCrypto cryptoContext) {
        super(cryptoContext);
    }

    @Override
    protected ByteArrayBuffer encrypt(RtpCrypto cryptoContext, ByteArrayBuffer plaintext) {

        SrtpErrorStatus errEncrypt = cryptoContext.encryptSrtp(plaintext);

        if (errEncrypt == SrtpErrorStatus.REPLAY_OLD || errEncrypt == SrtpErrorStatus.REPLAY_FAIL) {
            LOGGER.trace("encountered duplicate packet");
            return plaintext;
        }

        if (errEncrypt != SrtpErrorStatus.OK) {
            throw new RuntimeException("Failed SRTP encryption: " + errEncrypt.name());
        }

        return plaintext;
    }

    @Override
    protected byte[] intermediateToCipherBytes(ByteArrayBuffer intermediate) {
        byte[] array = new byte[intermediate.getLength()];
        System.arraycopy(
                intermediate.getBuffer(),
                0,
                array,
                intermediate.getOffset(),
                intermediate.getLength());
        return array;
    }

    @Override
    protected List<ByteArrayBuffer> parseToIntermediate(RtpCrypto cryptoContext, byte[] rawPacket) {
        int len = rawPacket.length;
        byte[] data_buffer = new byte[RtpCrypto.BUFFER_SIZE];
        System.arraycopy(rawPacket, 0, data_buffer, 0, len);
        return List.of(new ByteArrayBufferImpl(data_buffer, 0, len));
    }
}
