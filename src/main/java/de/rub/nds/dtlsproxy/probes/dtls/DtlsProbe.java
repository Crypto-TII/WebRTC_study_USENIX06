/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.exceptions.MissingProofException;
import de.rub.nds.dtlsproxy.probes.Probe;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.LocalConnectionProvider;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class DtlsProbe extends Probe {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String CLIENT_TO_ATTACKER_CONNECTION = "clientToAttacker";
    public static final String ATTACKER_TO_SERVER_CONNECTION = "serverToAttacker";

    private int executionAttempts = 0;
    private TestResult unProvenResult = null;

    protected DtlsProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    /**
     * Returns true if we will not try to execute the probe again after this execution
     *
     * @return True if we will not try to execute the probe again after this execution
     */
    protected final boolean executionAttemptsExceeded() {
        return executionAttempts + 1 >= getProxyConfiguration().getMaxExecutionRetries();
    }

    protected TestResult extractProofResult(WorkflowTrace trace) {
        ProtocolMessage lastMessage;
        if (trace.getLastReceivingAction().getReceivedMessages().isEmpty()) {
            lastMessage = null;
        } else {
            lastMessage =
                    trace.getLastReceivingAction()
                            .getReceivedMessages()
                            .get(trace.getLastReceivingAction().getReceivedMessages().size() - 1);
        }

        if (lastMessage instanceof AlertMessage) {
            LOGGER.debug("Received an Alert message. Found proof.");
            return new DetailedResult<String>(
                    TestResults.TRUE, "Received alert message: " + lastMessage.toCompactString());
        }

        unProvenResult =
                new DetailedResult<String>(
                        TestResults.TRUE,
                        "Received no alert. No proof. Last message: "
                                + (lastMessage == null
                                        ? "<no response>"
                                        : lastMessage.toCompactString()));

        if (executionAttemptsExceeded()) {
            return unProvenResult;
        } else {
            throw new MissingProofException();
        }
    }

    protected abstract void runChecks(WebRtcPlatformReport report);

    protected void execute(TraceableConnection connection, String name) {
        LOGGER.debug("Executing state: {}", name);

        Process serverProcess = null;

        if (getProxyConfiguration().getServerCommand() != null) {
            serverProcess = startServerProcess();
        }
        WorkflowExecutor executor = new DTLSWorkflowExecutor(connection.getState());

        if (getConnectionProvider() instanceof LocalConnectionProvider) {
            executor.setBeforeTransportInitCallback(createStartLocalClientFunction());
        }
        executor.executeWorkflow();
        getPostAnalyzer().consume(connection.getState(), connection.getConnectionInterface());
        if (serverProcess != null) {
            stopLocalServer(serverProcess);
        }

        LOGGER.debug(
                "Finished execution (executed as planned={})",
                connection.getState().getWorkflowTrace().executedAsPlanned());

        LOGGER.debug(
                "All actions executed: {}",
                connection.getState().getWorkflowTrace().allActionsExecuted());
        LOGGER.debug("Trace:{}", connection.getState().getWorkflowTrace());
    }

    public TestResult executeWithRetries(Callable<TestResult> function) {
        unProvenResult = null;
        executionAttempts = 0;
        String executionName = UUID.randomUUID().toString();
        while (true) {
            try {
                startCapture(this.getClass().getSimpleName() + "_" + executionName);
                return function.call();
            } catch (MissingProofException e) {
                LOGGER.info(
                        "Looking for proof ({} / {})",
                        executionAttempts + 1,
                        getProxyConfiguration().getMaxExecutionRetries());
                LOGGER.trace(e);
                executionAttempts++;
                if (executionAttempts >= getProxyConfiguration().getMaxExecutionRetries()) {
                    if (unProvenResult != null) {
                        // We exausted the maximum number of reexecutions but we have a result that
                        // is not proven atleast
                        return unProvenResult;
                    }
                    return new DetailedResult<Exception>(TestResults.ERROR_DURING_TEST, e);
                }
            } catch (Exception e) {
                LOGGER.debug("Execution raised Exception: {}", e.toString());
                LOGGER.trace("Execution Exception details: ", e);
                e.printStackTrace();
                executionAttempts++;
                if (executionAttempts >= getProxyConfiguration().getMaxExecutionRetries()) {
                    if (unProvenResult != null) {
                        // We exausted the maximum number of reexecutions but we have a result that
                        // is not proven atleast
                        return unProvenResult;
                    }
                    return new DetailedResult<Exception>(TestResults.ERROR_DURING_TEST, e);
                }
            } finally {
                endCapture(this.getClass().getSimpleName() + "_" + executionName);
            }
        }
    }

    private Process startServerProcess() {
        LOGGER.debug("Starting server");
        ProcessBuilder processBuilder =
                new ProcessBuilder("bash", "-c", getProxyConfiguration().getServerCommand());
        try {
            return processBuilder.start();
        } catch (IOException e) {
            throw new RuntimeException("Could not start server process", e);
        }
    }

    private Function<State, Integer> createStartLocalClientFunction() {
        return new Function<State, Integer>() {

            @Override
            public Integer apply(State state) {
                LocalConnectionProvider localConnectionProvider =
                        (LocalConnectionProvider) getConnectionProvider();
                if (state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                                .getConnection()
                                .getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    localConnectionProvider.prepareNextConnection();
                }
                return 0;
            }
        };
    }

    private void stopLocalServer(Process serverProcess) {
        LOGGER.debug("Destroying server process");
        serverProcess.destroy();
        LOGGER.debug("Server process destroyed");
    }

    protected TraceableConnection createConnection(Config config, WorkflowTrace trace) {
        return createConnection(
                config, trace, CLIENT_TO_ATTACKER_CONNECTION, ATTACKER_TO_SERVER_CONNECTION);
    }

    protected abstract List<WebRtcProperties> getRequiredProperties();
}
