/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.processing;

import de.rub.nds.dtlsproxy.util.ByteArrayWriteout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReencryptProcessor<T, I> extends Processor {

    protected static final Logger LOGGER = LogManager.getLogger();

    private Processor initialProcessor;

    private DecryptionProcessor<T, I> decryptionProcessor;
    private Processor firstIntermediateProcessor;
    private Processor lastIntermediateProcessor;
    private EncryptionProcessor<T, I> encryptionProcessor;

    private final ByteArrayWriteout writeToReceiver;

    private boolean encryptionEnabled = true;
    private boolean decryptionEnabled = true;

    public ReencryptProcessor(
            EncryptionProcessor<T, I> encryptionProcessor,
            DecryptionProcessor<T, I> decryptionProcessor,
            Processor intermediateProcessor,
            ByteArrayWriteout writeToReceiver) {
        this.initialProcessor = decryptionProcessor;
        this.encryptionProcessor = encryptionProcessor;
        this.decryptionProcessor = decryptionProcessor;
        this.firstIntermediateProcessor = intermediateProcessor;
        this.lastIntermediateProcessor = intermediateProcessor;
        this.writeToReceiver = writeToReceiver;

        hookProcessors();
    }

    @Override
    protected void process(byte[] data) {
        // propagates data through processing chain starting with decryption if enabled
        try {
            initialProcessor.input(data);
        } catch (Exception e) {
            LOGGER.trace("Failed re-encryption process: ", e);
        }
    }

    private void hookProcessors() {
        // hook chain
        decryptionProcessor.setNext(firstIntermediateProcessor);
        lastIntermediateProcessor.setNext(encryptionProcessor);
        encryptionProcessor.setNext(writeToReceiver);

        setEnableEncryption(encryptionEnabled);
        setEnableDecryption(decryptionEnabled);
    }

    public void setEnableDecryption(boolean enable) {
        if (enable) {
            initialProcessor = decryptionProcessor;
        } else {
            initialProcessor = firstIntermediateProcessor;
        }
        encryptionEnabled = enable;
    }

    public void setEnableEncryption(boolean enable) {
        if (enable) {
            lastIntermediateProcessor.setNext(encryptionProcessor);
        } else {
            lastIntermediateProcessor.setNext(writeToReceiver);
        }
        decryptionEnabled = enable;
    }

    public boolean dataReceived() {
        return wasDataProcessed();
    }

    public boolean encryptionSuccess() {
        return encryptionProcessor.wasCryptoSuccessful();
    }

    public boolean decryptionSuccess() {
        return decryptionProcessor.wasCryptoSuccessful();
    }

    public boolean isDecryptionEnabled() {
        return decryptionEnabled;
    }

    public boolean isEncryptionEnabled() {
        return encryptionEnabled;
    }

    public Processor getFirstIntermediateProcessor() {
        return firstIntermediateProcessor;
    }

    public void setFirstIntermediateProcessor(Processor firstIntermediateProcessor) {
        this.firstIntermediateProcessor = firstIntermediateProcessor;
        hookProcessors();
    }

    public Processor getLastIntermediateProcessor() {
        return lastIntermediateProcessor;
    }

    public void setLastIntermediateProcessor(Processor lastIntermediateProcessor) {
        this.lastIntermediateProcessor = lastIntermediateProcessor;
        hookProcessors();
    }

    public void setIntermediateProcessors(
            Processor firstIntermediateProcessor, Processor lastIntermediateProcessor) {
        this.firstIntermediateProcessor = firstIntermediateProcessor;
        this.lastIntermediateProcessor = lastIntermediateProcessor;
        hookProcessors();
    }

    public DecryptionProcessor<T, I> getDecryptionProcessor() {
        return decryptionProcessor;
    }

    public void setDecryptionProcessor(DecryptionProcessor<T, I> decryptionProcessor) {
        this.decryptionProcessor = decryptionProcessor;
        hookProcessors();
    }

    public EncryptionProcessor<T, I> getEncryptionProcessor() {
        return encryptionProcessor;
    }

    public void setEncryptionProcessor(EncryptionProcessor<T, I> encryptionProcessor) {
        this.encryptionProcessor = encryptionProcessor;
        hookProcessors();
    }
}
