/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.utils.simulate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class that provides a reading instance with a byte array if they are allowed to receive it, if
 * not the read will block until they are
 */
public class ControlledDataSource {

    @SuppressWarnings("unused")
    private static final Logger LOGGER = LogManager.getLogger();

    private final SimulationController controller;

    private final ConnectionSide connectionSide;

    /**
     * Creates a data source that will block read requests until the reader is permitted to receive
     * the data
     *
     * @param controller Controller for this stream
     * @param side ConnectionSide of this stream to request data for
     */
    public ControlledDataSource(SimulationController controller, ConnectionSide side) {
        this.controller = controller;
        this.connectionSide = side;
    }

    public byte[] fetchNext() {
        if (controller.permitsRead(connectionSide)) {
            final byte[] dataFetched = controller.getCurrentData();
            controller.finishTimeIndex(connectionSide);
            return dataFetched;
        } else {
            return new byte[0];
        }
    }
}
