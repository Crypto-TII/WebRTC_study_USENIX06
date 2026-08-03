/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;

/**
 * Stream-like mimic of an PipedInputStream, connected to a packet source. This stream is intended
 * to simulate a network peer, given the simulated actions of that peer, including timeouts between
 * read actions
 */
public class SimulatingInputStream extends PipedInputStream {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<ByteArrayInputStream> dataStreams;

    private final HashMap<ByteArrayInputStream, String> entrypointNames = new HashMap<>();

    int index = 0;

    /**
     * Creates a stream based on an action list given. No empty actions may be present as first or
     * last element. No two empty actions may be positioned next to each other in the list. Data
     * from not empty actions will be concatenated and returned during reading. When the end of that
     * data is encountered or an empty action is met a {@link SocketTimeoutException} is thrown.
     *
     * @param actions list of actions to simulate in order of injection
     * @throws IOException
     */
    @Deprecated
    public SimulatingInputStream(List<SimulatedAction> actions) throws IOException {
        dataStreams = mergeActions(actions, entrypointNames);
    }

    @Override
    public synchronized int read() throws IOException {
        if (index >= dataStreams.size()) {
            LOGGER.trace("Simulating timeout due to end of simulation");
            throw new SocketTimeoutException();
        }
        final ByteArrayInputStream stream = dataStreams.get(index);

        if (entrypointNames.containsKey(stream) && entrypointNames.get(stream) != null)
            LOGGER.trace("reading from simulated packet: {}", entrypointNames.get(stream));
        else LOGGER.trace("reading from noname simulated packet");

        if (stream.available() > 0) {
            return stream.read();
        }

        index++;
        LOGGER.trace("Simulating timeout due to end of simulated packets");
        throw new SocketTimeoutException();
    }

    @Override
    public synchronized int read(byte[] b, int off, int len) throws IOException {
        if (index >= dataStreams.size()) {
            LOGGER.trace("Simulating timeout due to end of simulation");
            throw new SocketTimeoutException();
        }

        final ByteArrayInputStream stream = dataStreams.get(index);

        if (entrypointNames.containsKey(stream) && entrypointNames.get(stream) != null)
            LOGGER.trace("reading from simulated packet: {}", entrypointNames.get(stream));
        else LOGGER.trace("reading from noname simulated packet");

        if (stream.available() > 0) {
            return stream.read(b, off, len);
        }

        index++;
        LOGGER.trace("Simulating timeout due to end of simulated packets");
        throw new SocketTimeoutException();
    }

    @Override
    public int read(@NotNull byte[] b) throws IOException {
        if (index >= dataStreams.size()) {
            LOGGER.trace("Simulating timeout due to end of simulation");
            throw new SocketTimeoutException();
        }
        final ByteArrayInputStream stream = dataStreams.get(index);

        if (entrypointNames.containsKey(stream) && entrypointNames.get(stream) != null)
            LOGGER.trace("reading from simulated packet: {}", entrypointNames.get(stream));
        else LOGGER.trace("reading from noname simulated packet");

        if (stream.available() > 0) {
            return stream.read(b);
        }

        index++;
        LOGGER.trace("Simulating timeout due to end of simulated packets");
        throw new SocketTimeoutException();
    }

    @Override
    public int readNBytes(byte[] b, int off, int len) throws IOException {
        if (index >= dataStreams.size()) {
            LOGGER.trace("Simulating timeout due to end of simulated data");
            throw new SocketTimeoutException();
        }
        final ByteArrayInputStream stream = dataStreams.get(index);

        if (entrypointNames.containsKey(stream) && entrypointNames.get(stream) != null)
            LOGGER.trace("reading from simulated packet: {}", entrypointNames.get(stream));
        else LOGGER.trace("reading from noname simulated packet");

        if (stream.available() > 0) {
            return stream.readNBytes(b, off, len);
        }

        index++;
        LOGGER.trace("Simulating timeout due to end of simulated packets");
        throw new SocketTimeoutException();
    }

    @Override
    public synchronized int available() throws IOException {
        if (index >= dataStreams.size()) {
            LOGGER.trace("Simulating timeout due to end of simulation");
            throw new SocketTimeoutException();
        }
        final int avail = dataStreams.get(index).available();
        if (avail == 0) {
            // try starting the next stream if there is one
            if (index == dataStreams.size() - 1) throw new SocketTimeoutException();
            index++;
        }
        return avail;
    }

    /**
     * Transforms list of actions into list of bytearray-streams by concatenating nearby actions and
     * starting a new stream when an empty action is met
     *
     * @param actions
     * @param entrypointNames map for storing first packet names for each byte stream if names are
     *     given
     * @return
     * @throws IOException
     */
    private static List<ByteArrayInputStream> mergeActions(
            List<SimulatedAction> actions, HashMap<ByteArrayInputStream, String> entrypointNames)
            throws IOException {

        // assume no NONE action in the beginning or end and no two NONE next to each other

        if (actions.isEmpty()) // empty simulation
        return new ArrayList<>();

        if (actions.get(0).getBytes() == null || actions.get(actions.size() - 1).getBytes() == null)
            throw new IllegalArgumentException(
                    "First and last simulated action must not be a timeout action");

        final List<ByteArrayInputStream> list = new ArrayList<>();

        ByteArrayOutputStream current = new ByteArrayOutputStream();

        String firstActionName = null;

        for (SimulatedAction action : actions) {
            if (action.getBytes() == null) {
                ByteArrayInputStream inputStream = new ByteArrayInputStream(current.toByteArray());
                if (firstActionName != null) entrypointNames.put(inputStream, firstActionName);
                list.add(inputStream);
                current.close();
                current = new ByteArrayOutputStream();
                firstActionName = null;
            } else {
                current.write(action.getBytes());
                if (firstActionName == null) firstActionName = action.getName();
            }
        }

        ByteArrayInputStream finalInputStream = new ByteArrayInputStream(current.toByteArray());
        if (firstActionName != null) entrypointNames.put(finalInputStream, firstActionName);
        list.add(finalInputStream);

        return list;
    }
}
