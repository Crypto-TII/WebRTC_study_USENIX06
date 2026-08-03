/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import de.rub.nds.dtlsproxy.utils.PacketLibrary;

/** Represents an inbound package or a point in time where no packages are buffered for receiving */
public class SimulatedAction {

    protected final byte[] payload;
    private String name;

    private int timeIndex;

    private ConnectionSide connectionSide;

    public SimulatedAction(int timeIndex, ConnectionSide connectionSide, byte[] payload) {
        this.timeIndex = timeIndex;
        this.payload = payload;
        this.connectionSide = connectionSide;
    }

    public SimulatedAction(
            int timeIndex, ConnectionSide connectionSide, byte[] payload, String name) {
        this.timeIndex = timeIndex;
        this.payload = payload;
        this.name = name;
        this.connectionSide = connectionSide;
    }

    public byte[] getBytes() {
        return payload;
    }

    public String getName() {
        return name;
    }

    public int getTimeIndex() {
        return timeIndex;
    }

    public ConnectionSide getConnectionSide() {
        return connectionSide;
    }

    /** Resembles simulating a moment where no packets are arriving */
    public static SimulatedAction none(int index, ConnectionSide side) {
        return new SimulatedAction(index, side, null);
    }

    /** Simulates the arrival of a fatal alert 'bad certificate' */
    public static SimulatedAction alertBadCert(int index, ConnectionSide side) {
        return new SimulatedAction(index, side, PacketLibrary.ALERT_BAD_CERT, "Alert BAD_CERT");
    }
}
