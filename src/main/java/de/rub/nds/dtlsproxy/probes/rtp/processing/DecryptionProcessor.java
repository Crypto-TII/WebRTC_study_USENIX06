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

public abstract class DecryptionProcessor<T, I> extends CryptoProcessor<T, I> {

    public DecryptionProcessor(T cryptoContext) {
        super(cryptoContext);
    }

    @Override
    protected List<byte[]> performCrypto(byte[] data) {
        List<I> intermediatePlain = parseToIntermediate(cryptoContext, data);
        List<I> intermediateDecrypted =
                intermediatePlain.stream()
                        .map(i -> decrypt(cryptoContext, i))
                        .collect(Collectors.toList());
        return intermediateDecrypted.stream()
                .map(this::intermediateToPlainBytes)
                .collect(Collectors.toList());
    }

    /**
     * Decrypts the given ciphertext intermediate with the given crypto context
     *
     * @param cryptoContext context that applies decryption functionality
     * @param ciphertext ciphertext intermediate object after read and parsed from stream
     * @return decrypted intermediate
     */
    protected abstract I decrypt(T cryptoContext, I ciphertext);

    /**
     * Converts the intermediate object to a byte array to be printed by the logger
     *
     * @param intermediate decrypted intermediate
     * @return plain bytes
     */
    protected abstract byte[] intermediateToPlainBytes(I intermediate);
}
