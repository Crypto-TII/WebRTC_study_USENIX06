/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.provider;

import de.rub.nds.dtlsproxy.booter.Booter;
import de.rub.nds.dtlsproxy.booter.BooterFactory;
import de.rub.nds.dtlsproxy.booter.ManualBooter;
import de.rub.nds.dtlsproxy.booter.TargetNotStartingException;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.config.TargetConfig;
import de.rub.nds.dtlsproxy.enums.Browser;
import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.provider.proxy.ConnectionNotRetrievableException;
import de.rub.nds.dtlsproxy.provider.proxy.HookedConnection;
import de.rub.nds.dtlsproxy.provider.proxy.SessionManager;
import de.rub.nds.dtlsproxy.report.ConnectionCreationReport;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.Capabilities;

/**
 * A Connection Provider that creates connections by using a Booter and a PacketFilter. as required
 * for a WebRTC connection. The Booter is used to start a WebRTC connection, typically by starting a
 * browser with Selenium and then pressing the respective buttons in the browser to start the
 * connection. The UDP packets of the WebRTC connection are then forwarded through the gateway to
 * the PacketFilter. The PacketFilter tries to find newly created DTLS connections and returns them
 * to the Connection Provider. Other packets are forwarded through.
 */
public class ProxiedConnectionProvider implements ConnectionProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private ConnectionCreationReport report;

    /** Booter used to start the client */
    private Booter booter;

    /** counts how many connections have been created so far */
    private int connectionCounter = 0;

    /**
     * The timeout in seconds from starting a DTLS connection until we catch it with the packet
     * filter
     */
    private final long targetTimeout;

    private final int maxRetries;

    /** to keep track of the access rate */
    private long timeOfStart;

    private int booterStarts;

    private float rateLimit;

    private boolean doFastResets;

    private SessionManager sessionManager;

    private FilterDirection lockFilterDirection = null;

    private int sessionResetPauseDuration = 0;

    private boolean promptUserForReset = true;

    /**
     * Creates a new ProxiedConnectionProvider
     *
     * @param targetConfig Config for web service access
     * @param capabilities Browser settings
     * @param proxyConfiguration Analysis tool settings
     * @param browser browser type
     * @param sessionManager The session manager that keeps track of session
     */
    public ProxiedConnectionProvider(
            TargetConfig targetConfig,
            Capabilities capabilities,
            ProxyConfiguration proxyConfiguration,
            Browser browser,
            SessionManager sessionManager) {
        this.sessionManager = sessionManager;
        this.targetTimeout = proxyConfiguration.getTargetTimeout();
        this.timeOfStart = System.currentTimeMillis();
        this.doFastResets = proxyConfiguration.isFastReset();
        this.maxRetries = proxyConfiguration.getMaxConnectionRetries();
        this.sessionResetPauseDuration = proxyConfiguration.getSessionResetPause();
        this.promptUserForReset = proxyConfiguration.getSessionResetPause() == 0;
        booterStarts = 0;
        rateLimit = proxyConfiguration.getRateLimit();
        booter =
                BooterFactory.createBooter(targetConfig, capabilities, proxyConfiguration, browser);
        report = new ConnectionCreationReport();
    }

    @Override
    public synchronized HookedConnection createConnection() {
        LOGGER.debug("Starting DTLS connection in booter and catching it with the PacketFilter");
        clearPipeline();
        HookedConnection hookedConnection = fetchConnection();
        report.addConnection(hookedConnection);
        LOGGER.debug("Created connection");
        connectionCounter++;
        return hookedConnection;
    }

    /**
     * Retrieves the next connection without calling a booter. If a connection match is not found in
     * the current session, no reset is issued and a ConnectionNoRetrievableException is thrown
     */
    @Override
    public ConnectionInterface nextConnection() {
        LOGGER.debug(
                "Awaiting DTLS connection without booter and catching it with the PacketFilter");
        clearPipeline();
        HookedConnection hookedConnection = sessionManager.fetchFreshConnection();
        report.addConnection(hookedConnection);
        LOGGER.debug("Caught connection");
        connectionCounter++;
        return hookedConnection;
    }

    private void clearPipeline() {
        /**
         * LOGGER.info("CLOSE EXISTING CONNECTIONS. Press any key to continue:"); try {
         * System.in.read(); } catch (IOException e) { // TODO Auto-generated catch block
         * e.printStackTrace(); }
         */
        LOGGER.trace("Clearing old connections in the pipeline.");
        sessionManager.drainConnections();
    }

    @Override
    public void prepareNextConnection() {
        prepareNextConnection(false);
    }

    /**
     * Resets the session and fires up the booter but does not block for a connection
     *
     * @param disableFiltering whether to wildcard match handshakes instead of filtering them or hs
     *     nr / ja3 fingerprint etc (use this for probes with multiple connections)
     */
    public void prepareNextConnection(boolean disableFiltering) {
        sessionManager.prepareNext(disableFiltering);
        resetBooter();
        clearPipeline();
        booter.startDtlsConnection();
    }

    private HookedConnection fetchConnection() {
        LOGGER.debug("Starting fetching a connection (nr {})", connectionCounter + 1);
        int restartCounter = 0;

        do {
            try {
                if (restartCounter >= maxRetries) {
                    // stop trying
                    LOGGER.warn("Hit max retries for connection. Calling it quits.");
                    booter.close();
                    break;
                }

                // ensure rate limit
                rateLimitWait();

                AtomicReference<HookedConnection> nextConnection = new AtomicReference<>();
                // blocks until CH received or connection deemed impossible

                waitForSessionEnd();

                checkTimeout(
                        () -> {
                            prepareNextConnection();
                            try {
                                nextConnection.set(sessionManager.fetchFreshConnection());
                            } catch (ConnectionNotRetrievableException e) {
                                // booter reset required
                                nextConnection.set(null);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
                booterStarts++;
                HookedConnection connection = nextConnection.get();

                if (connection == null) {
                    LOGGER.debug("Connection not retrievable in this session, retrying...");
                    resetBooter();
                    restartCounter++;
                    continue;
                }

                if (lockFilterDirection != null
                        && connection.getCreatedFromFilterDirection() != lockFilterDirection) {
                    LOGGER.warn(
                            "Connection not in locked direction '{}', retrying...",
                            lockFilterDirection);
                    sessionManager.release(connection);
                    resetBooter();
                    restartCounter++;
                    continue;
                }

                return connection;

            } catch (Exception e) {
                LOGGER.warn("Failed to get connection, retrying...");
                LOGGER.debug("Details", e);
                restartCounter++;
            }
        } while (true);
        throw new TargetNotStartingException(
                "Failed to fetch connection even after reset attempts");
    }

    public void waitForSessionEnd() {
        if (!(booter instanceof ManualBooter)) {
            return;
        }
        if (sessionManager.getDtlsSessionsPerCall() == 1) {
            return;
        }
        if (connectionCounter == 0) {
            return;
        }

        if (sessionManager.dtlsSessionsPerCallUnknown()
                || sessionManager.getDtlsSessionsPerCall() > 1) {
            // we must wait for the user to close the current call to prevent selecting a
            // dtls connection that is not part of a new session
            resetPause();
        }
    }

    private void resetPause() {
        if (promptUserForReset) {
            LOGGER.info("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~");
            LOGGER.info("END OLD CALL and confirm with any key...");
            LOGGER.info("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~");
            try {
                System.in.read();
            } catch (IOException e) {
                LOGGER.debug("Error while waiting for user input", e);
            }
            LOGGER.info("Continuing with new call... wait for instructions");
        } else {
            LOGGER.info("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~");
            LOGGER.info("END OLD CALL and wait...");
            LOGGER.info("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~");
            try {
                Thread.sleep(sessionResetPauseDuration);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /** blocks until user set rate limit met */
    private void rateLimitWait() {
        float rate =
                booterStarts / (1 + (System.currentTimeMillis() - timeOfStart) / (60 * 1000.0f));
        LOGGER.debug("Rate is {} connections / minute", rate);
        if (rate > rateLimit) {
            long timeToWait =
                    (long)
                            (1
                                    + (60 * 1000 * booterStarts / rateLimit)
                                    - (System.currentTimeMillis() - timeOfStart));
            LOGGER.debug("Rate limit hit, waiting {} ms", timeToWait);
            try {
                if (timeToWait > 0) Thread.sleep(timeToWait);
            } catch (InterruptedException e) {
            }
        }
    }

    private void checkTimeout(Runnable connectionFetch) {

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<?> future = executor.submit(connectionFetch);

        try {
            future.get(targetTimeout, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // Cancel the task if it times out
            future.cancel(true);
            throw new RuntimeException(e);
        } catch (ExecutionException | InterruptedException e) {
            // Handle other exceptions that might occur during task execution
            throw new RuntimeException("Task execution failed", e);
        } finally {
            executor.shutdownNow();
        }
    }

    private void resetBooter() {
        if (doFastResets) {
            if (!booter.softReset()) {
                LOGGER.trace(
                        "Soft booter reset failed / not implemented. Defaulting to hard reset");
                booter.hardReset();
            }
        } else {
            booter.hardReset();
        }
    }

    @Override
    public String getProviderName() {
        return booter.getTargetName();
    }

    @Override
    public void release(ConnectionInterface connection) {
        sessionManager.release((HookedConnection) connection);
        resetBooter();
    }

    @Override
    public void release(ConnectionInterface connection, boolean forceHardReset) {
        sessionManager.release((HookedConnection) connection);
        if (forceHardReset) {
            booter.hardReset();
        } else {
            resetBooter();
        }
    }

    @Override
    public void closeProvider() {
        booter.close();
    }

    @Override
    public void lockInFilterDirection(FilterDirection direction) {
        this.lockFilterDirection = direction;
    }

    @Override
    public ConnectionCreationReport getConnectionCreationReport() {
        return report;
    }

    @Override
    public int getConnectionCounter() {
        return connectionCounter;
    }
}
