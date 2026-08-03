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
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class RepeatingSimulation extends Simulation {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<SimulatedAction> actions;

    private ControlledDataSource clientSource;
    private ControlledDataSource serverSource;

    private SimulationController controller;

    protected RepeatingSimulation(List<SimulatedAction> actions) {
        this.actions = actions;
        this.controller = new SimulationController(new ArrayList<>(actions));
        this.clientSource = new ControlledDataSource(this.controller, ConnectionSide.CLIENT);
        this.serverSource = new ControlledDataSource(this.controller, ConnectionSide.SERVER);
    }

    @Override
    public ControlledDataSource getCurrentClientSource() {
        return clientSource;
    }

    @Override
    public ControlledDataSource getCurrentServerSource() {
        return serverSource;
    }

    @Override
    public void prepareNext() {
        LOGGER.debug("restarting simulation");
        this.controller = new SimulationController(new ArrayList<>(actions));
        this.clientSource = new ControlledDataSource(this.controller, ConnectionSide.CLIENT);
        this.serverSource = new ControlledDataSource(this.controller, ConnectionSide.SERVER);
    }
}
