/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import java.util.List;
import java.util.stream.Collectors;

public abstract class EncryptionProcessor<T, I> extends CryptoProcessor<T, I> {

    public EncryptionProcessor(T cryptoContext) {
        super(cryptoContext);
    }

    @Override
    protected List<byte[]> performCrypto(byte[] data) {
        List<I> intermediatePlain = parseToIntermediate(cryptoContext, data);
        List<I> intermediateEncrypted =
                intermediatePlain.stream()
                        .map(i -> encrypt(cryptoContext, i))
                        .collect(Collectors.toList());
        return intermediateEncrypted.stream()
                .map(this::intermediateToCipherBytes)
                .collect(Collectors.toList());
    }

    /**
     * Encrypts the given plaintext intermediate with the given crypto context
     *
     * @param cryptoContext context that applies encryption functionality
     * @param plaintext plaintext intermediate object after decryption
     * @return encrypted intermediate
     */
    protected abstract I encrypt(T cryptoContext, I plaintext);

    /**
     * Serializes the encrypted intermediate object to a byte array
     *
     * @param intermediate encrypted intermediate value
     */
    protected abstract byte[] intermediateToCipherBytes(I intermediate);
}
