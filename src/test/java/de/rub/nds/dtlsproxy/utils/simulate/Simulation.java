/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import java.util.List;

public abstract class Simulation {

    protected Simulation() {}

    public abstract ControlledDataSource getCurrentClientSource();

    public abstract ControlledDataSource getCurrentServerSource();

    public abstract void prepareNext();

    /**
     * Creates a repeating simulation instance from action lists. Repeats after each prepareNext
     * call
     */
    public static Simulation repeating(List<SimulatedAction> actions) {
        return new RepeatingSimulation(actions);
    }

    /**
     * Creates repeating simulation instance from action lists. Progresses to next list after each
     * prepareNext call
     */
    @SafeVarargs
    public static Simulation continuous(List<SimulatedAction>... actions) {
        return new ContinuousSimulation(actions);
    }
}
