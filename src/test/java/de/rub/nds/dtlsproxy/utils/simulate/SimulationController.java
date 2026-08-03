/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SimulationController {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Contains data to be read in the simulation, a null entry indicates a timeout */
    private final List<byte[]> data;

    /** Contains a side to simulate while reading the data from the data array */
    private final ConnectionSide[] dataSides;

    /** Contains debug information about the current step */
    private final String[] dataInformation;

    private int currentTimeIndex = 0;

    /**
     * Creates a simulation ready controller from actions to simulate. The data is ordered by index
     * value of each action, order in actions list does not matter. This constructor creates a copy
     * of the original list before writing.
     */
    public SimulationController(List<SimulatedAction> actions) {

        // create copy of actions not to alter original data
        actions = new ArrayList<>(actions);

        // sort actions by time index to achieve order
        actions.sort(Comparator.comparingInt(SimulatedAction::getTimeIndex));

        // --- create data and side arrays ---
        data = new ArrayList<>();
        dataSides = new ConnectionSide[actions.size()];
        dataInformation = new String[actions.size()];

        LOGGER.trace("Simulation Controller instantiated:");

        // iterate actions and copy data and side
        for (int i = 0; i < actions.size(); i++) {

            final SimulatedAction a = actions.get(i);
            if (a.getBytes() == null) {
                // this is a timeout action
                data.add(i, null);
            } else {
                // this is a data action
                data.add(i, a.getBytes());
            }

            dataSides[i] = a.getConnectionSide();
            dataInformation[i] = a.getName();
            LOGGER.trace("{}, {}, {}", i, a.getConnectionSide(), a.getName());
        }
    }

    /** Returns the current debug information */
    protected synchronized String getCurrentInfo() {

        if (currentTimeIndex >= data.size())
            throw new RuntimeException("Operation impossible as simulation concluded");

        return dataInformation[currentTimeIndex];
    }

    /** Returns the stream to read from in this step */
    protected synchronized byte[] getCurrentData() {

        if (currentTimeIndex >= data.size())
            throw new RuntimeException("Operation impossible as simulation concluded");

        return data.get(currentTimeIndex);
    }

    /** Checks wether the given connection side is appointed for reading in the current step */
    protected synchronized boolean permitsRead(ConnectionSide currentSide) {
        return currentTimeIndex < data.size() && dataSides[currentTimeIndex] == currentSide;
    }

    /** Indicates to progress the simulation by one step as reading a data section has finished */
    protected synchronized void finishTimeIndex(ConnectionSide currentSide) {

        // guards
        if (currentTimeIndex >= data.size()) {
            throw new RuntimeException("Operation impossible as simulation concluded");
        }

        if (currentSide != dataSides[currentTimeIndex]) {
            throw new RuntimeException(
                    "Invalid state, the given connection side was not appointed the finished time index");
        }

        currentTimeIndex++;

        // wake up a sleeping thread if existing
        if (currentTimeIndex < dataSides.length) {
            synchronized (dataSides[currentTimeIndex]) {
                dataSides[currentTimeIndex].notify();
            }
        }
    }

    protected void awaitProgression(ConnectionSide sideRequired) {
        synchronized (sideRequired) {
            try {
                sideRequired.wait();
            } catch (InterruptedException ignored) {
            }
        }
    }

    protected List<byte[]> getData() {
        return data;
    }

    protected ConnectionSide[] getDataSides() {
        return dataSides;
    }

    protected String[] getDataInformation() {
        return dataInformation;
    }

    protected int getCurrentTimeIndex() {
        return currentTimeIndex;
    }
}
