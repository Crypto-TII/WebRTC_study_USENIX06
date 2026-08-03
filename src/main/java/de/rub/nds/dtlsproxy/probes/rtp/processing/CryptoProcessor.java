/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Encrypts or decrypts input data and forwards it to a single output
 *
 * @param <T> Cryptographic handler f.e. TlsContext
 * @param <I> Intermediate datatype used by cryptographic handler f.e. Record
 */
public abstract class CryptoProcessor<T, I> extends Processor {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final T cryptoContext;

    /** Whether the encryption/decryption took place at least ones without errors */
    private boolean cryptoSuccessful;

    public CryptoProcessor(T cryptoContext) {
        this.cryptoContext = cryptoContext;
    }

    @Override
    protected void process(byte[] data) {

        List<byte[]> cryptoResult = performCrypto(data);

        if (cryptoResult != null && !cryptoResult.isEmpty() && cryptoResult.get(0).length > 0) {
            cryptoSuccessful = true;
            try {
                for (byte[] result : cryptoResult) {
                    output(result);
                }
            } catch (IOException e) {
                LOGGER.warn("Failed to write cryptographical result to output: ", e);
            }
        }
    }

    /**
     * Prepares bytes read from the input stream to be passed to the crypto context for decryption
     *
     * @param cryptoContext crypto context
     * @param rawPacket byte array from the input stream
     * @return intermediate object to apply decryption on
     */
    protected abstract List<I> parseToIntermediate(T cryptoContext, byte[] rawPacket);

    /**
     * Performs the cryptographic operation, returning the cryptographic result. If the operation
     * fails, null is returned.
     *
     * @param data input data to transform
     * @return transformed data or null on failure
     */
    protected abstract List<byte[]> performCrypto(byte[] data);

    public boolean wasCryptoSuccessful() {
        return cryptoSuccessful;
    }
}
