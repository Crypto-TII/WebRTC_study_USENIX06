/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.report.ConnectionCreationReport;

/**
 * Interface for Connection Providers. Connection Providers are used to create new connections and
 * to terminate them.
 */
public interface ConnectionProvider {
    public abstract ConnectionInterface createConnection();

    /**
     * Does not take any steps to retrieve a DTLS connection but will kick off a connection creating
     * procedure
     */
    public abstract void prepareNextConnection();

    /** Blocks and returns the next connection available without initiating a new call */
    public abstract ConnectionInterface nextConnection();

    public abstract String getProviderName();

    /**
     * Removes the connection from the examination stack
     *
     * @param connection Connection to be released
     */
    public abstract void release(ConnectionInterface connection);

    /**
     * Removes the connection from the examination stack with the option to force a hard reset for
     * the service operator
     *
     * @param connection Connection to be released
     * @param forceHardReset wether to force a hard reset
     */
    public default void release(ConnectionInterface connection, boolean forceHardReset) {
        release(connection);
    }

    /** Closes remote drivers linked to this provider */
    public abstract void closeProvider();

    /**
     * Only allows new connections from the chosen filter connection direction if null is passed,
     * all directions are allowed
     */
    public void lockInFilterDirection(FilterDirection direction);

    public ConnectionCreationReport getConnectionCreationReport();

    public default int getConnectionCounter() {
        return 0;
    }
}
