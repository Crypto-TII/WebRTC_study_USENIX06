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
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Receives byte data through queue or ByteArrayWriteout interface, processes data and writes to
 * registered ByteArrayWriteouts
 */
public abstract class Processor implements ByteArrayWriteout {

    protected static final Logger LOGGER = LogManager.getLogger();

    private ByteArrayWriteout next;

    private boolean dataProcessed = false;

    private boolean closed = false;

    /**
     * Used internaly. Use write for calls from external
     *
     * @param data
     * @throws IOException
     */
    protected abstract void process(byte[] data) throws IOException;

    protected ByteArrayWriteout getNext() {
        return next;
    }

    public void setNext(ByteArrayWriteout next) {
        this.next = next;
    }

    /**
     * Calls the set ByteArrayWriteout class with the given data
     *
     * @param data
     */
    protected void output(byte[] data) throws IOException {
        if (this.next == null) {
            // no output configured
            return;
        }
        this.next.input(data);
    }

    @Override
    public void input(byte[] data) throws IOException {
        if (closed) {
            throw new IOException("Processor closed.");
        }
        process(data);
        dataProcessed = true;
    }

    /**
     * If the processor is to take proactive action, this method will cause this action. The method
     * is to be called by a controlling instance after connection setup at an appropriate, context
     * depending, timing
     */
    public void start() throws IOException {}

    public boolean wasDataProcessed() {
        return dataProcessed;
    }

    /**
     * Closes the processor and its components, as well as the output processor chained to it.
     * Overwrite this method and call the super version to integrate closing of IO streams etc.
     */
    public void close() {
        closed = true;
        // propagate close operation to chained processor
        if (this.next != null && this.next instanceof Processor) {
            ((Processor) this.next).close();
        }
    }

    public boolean isClosed() {
        return closed;
    }
}
