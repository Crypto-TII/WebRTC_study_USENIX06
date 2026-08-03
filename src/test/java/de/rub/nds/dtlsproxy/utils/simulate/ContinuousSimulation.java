/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class ContinuousSimulation extends Simulation {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<SimulatedAction>[] actions;

    private ControlledDataSource clientSource;
    private ControlledDataSource serverSource;

    /** Keeps track which list of actions is next for the next provider creation */
    private int counter = 0;

    private SimulationController currentController;

    protected ContinuousSimulation(List<SimulatedAction>[] actions) {
        if (actions.length == 0)
            throw new IllegalArgumentException("Action-Sequence arrays must not be empty");
        this.actions = actions;
    }

    @Override
    public ControlledDataSource getCurrentClientSource() {
        if (counter == 0) {
            throw new RuntimeException("Simulation not prepared");
        }
        return clientSource;
    }

    @Override
    public ControlledDataSource getCurrentServerSource() {
        if (counter == 0) {
            throw new RuntimeException("Simulation not prepared");
        }
        return serverSource;
    }

    @Override
    public void prepareNext() {

        // last simulation already prepared
        if (counter >= actions.length) {
            LOGGER.debug("Not advancing simulation because end reached");
            return;
        }

        this.currentController = new SimulationController(actions[counter]);
        this.clientSource = new ControlledDataSource(currentController, ConnectionSide.CLIENT);
        this.serverSource = new ControlledDataSource(currentController, ConnectionSide.SERVER);

        counter++;

        LOGGER.debug("Advancing simulation to step {}", counter);
    }
}
