/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.report.ConnectionCreationReport;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A connection provider for cases where the client and the server can both be started locally. The
 * connection provider uses the client command from the configuration to start the client. And
 * assumes that the server is already running.
 */
public class LocalConnectionProvider implements ConnectionProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProxyConfiguration proxyConfiguration;

    /** The process of the local dtls client */
    private Process clientProcess = null;

    private ConnectionCreationReport report;

    public LocalConnectionProvider(ProxyConfiguration proxyConfiguration) {
        this.proxyConfiguration = proxyConfiguration;
        report = new ConnectionCreationReport();
    }

    @Override
    public LocalConnection createConnection() {
        LocalConnection connection = new LocalConnection(proxyConfiguration);
        report.addConnection(connection);
        return connection;
    }

    @Override
    public ConnectionInterface nextConnection() {
        return createConnection();
    }

    @Override
    public void prepareNextConnection() {
        // start local DTLS client
        try {
            LOGGER.debug(
                    "Starting local DTLS client 'bash -c {}'",
                    proxyConfiguration.getClientCommand());
            ProcessBuilder processBuilder =
                    new ProcessBuilder("bash", "-c", proxyConfiguration.getClientCommand());
            clientProcess = processBuilder.start();
            LOGGER.debug("Finished starting local DTLS client");
        } catch (IOException e) {
            throw new RuntimeException("Cannot start DTLS client");
        }
    }

    @Override
    public String getProviderName() {
        return "local";
    }

    @Override
    public void release(ConnectionInterface connection) {
        if (clientProcess != null && clientProcess.isAlive()) {
            LOGGER.debug("Terminating local DTLS client");
            clientProcess.destroy();
        }
    }

    @Override
    public void closeProvider() {}

    @Override
    public void lockInFilterDirection(FilterDirection direction) {
        // Not Implemented
    }

    @Override
    public ConnectionCreationReport getConnectionCreationReport() {
        return report;
    }
}
