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
import java.util.concurrent.BlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Loops as long as the timeout is not reached and inputs data to a processor */
public class ProcessorInput implements Runnable {

    protected static final Logger LOGGER = LogManager.getLogger();

    private long inputDuration = Long.MAX_VALUE;

    private final BlockingQueue<byte[]> inputQueue;

    private Processor processor;

    private Thread thread;

    public ProcessorInput(BlockingQueue<byte[]> inputQueue, Processor processor) {
        this.inputQueue = inputQueue;
        this.processor = processor;
    }

    public ProcessorInput(
            BlockingQueue<byte[]> inputQueue, Processor processor, long inputDuration) {
        this.inputQueue = inputQueue;
        this.processor = processor;
        this.inputDuration = inputDuration;
    }

    @Override
    public void run() {

        try {
            processor.start();
        } catch (IOException e) {
            LOGGER.warn("Failed to kick off processing: ", e);
            throw new RuntimeException(e);
        }

        final long startTime = System.currentTimeMillis();

        while ((System.currentTimeMillis() - startTime) < inputDuration) {

            byte[] input;

            try {
                input = inputQueue.take();
            } catch (InterruptedException ignored) {
                // Thread termination
                break;
            }

            try {
                processor.input(input);
            } catch (Exception e) {
                LOGGER.trace("Data processing failed: ", e);
            }
        }
    }

    public void startThread(String label) {
        this.thread = new Thread(this, label);
        thread.start();
    }

    public void startThread(ThreadGroup group, String label) {
        this.thread = new Thread(group, this, label);
        thread.start();
    }

    public void joinThread() {
        try {
            thread.join(inputDuration);
        } catch (InterruptedException ignored) {
        }
    }
}
