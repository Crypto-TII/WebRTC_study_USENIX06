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
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerCipherSuiteProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<CipherSuite> functionalCipherSuites = new LinkedList<>();

    public ServerCipherSuiteProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        LOGGER.info("Testing which cipher suites are supported by the server");
        functionalCipherSuites = new LinkedList<>();

        LOGGER.trace(
                "Trying to determine the size of the largest responsive cipher suite offer...");

        int maxAcceptedCiphers = getLargestResponsiveCipherSuiteOffer(report).size();

        List<CipherSuite> offeredCipherSuites = getTestableCipherSuites();
        List<CipherSuite> supportedCipherSuites = new ArrayList<>();

        LOGGER.debug(
                "Determined that the server accepts ClientHellos with at most {} ciphers,"
                        + " including client offered ciphers",
                maxAcceptedCiphers);

        do {
            LOGGER.trace(
                    "We have {} remaining cipher suites to test for and determined the server accepts at max {} at once, so we present them {} ",
                    offeredCipherSuites.size(),
                    maxAcceptedCiphers,
                    Math.min(maxAcceptedCiphers, offeredCipherSuites.size()));
            // offer a cipher set of maximum size to the server until they have seen all
            List<CipherSuite> newOfferedCipherSuites = new ArrayList<>();
            final int offerSize = Math.min(maxAcceptedCiphers, offeredCipherSuites.size());
            for (int i = 0; i < offerSize; i++) {
                newOfferedCipherSuites.add(offeredCipherSuites.removeFirst());
            }
            LOGGER.trace(
                    "Presenting to the server: {}",
                    offeredCipherSuites.stream().map(Enum::name).collect(Collectors.joining(", ")));
            supportedCipherSuites.addAll(getSupportedCipherSuites(report, newOfferedCipherSuites));
        } while (!offeredCipherSuites.isEmpty());

        if (supportedCipherSuites.isEmpty()) {
            // we are probably in early profiling so it would be ok to abort the tool here
            throw new RuntimeException("Server did not pick any cipher suites.");
        }

        report.setServerSupportedCipherSuites(supportedCipherSuites);
        LOGGER.trace(
                "Determined server supported cipher suites: {}",
                supportedCipherSuites.stream().map(Enum::name).collect(Collectors.joining(", ")));
        report.setFunctionalServerSupportedCipherSuites(functionalCipherSuites);
        if (supportedCipherSuites.size() > 1) {
            LOGGER.trace("performing order enforcement check");
            report.putResult(
                    WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_CIPHER_SUITES,
                    getEnforcesCipherSuiteOrder(report, supportedCipherSuites));
        } else {
            report.putResult(
                    WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_CIPHER_SUITES,
                    TestResults.CANNOT_BE_TESTED);
        }
    }

    private List<CipherSuite> getLargestResponsiveCipherSuiteOffer(WebRtcPlatformReport report) {
        List<CipherSuite> offeredCipherSuites =
                new ArrayList<>(report.getClientSupportedCipherSuites());

        final int maxUsableCipherSuiteCount = fillToSuiteAmount(report, Integer.MAX_VALUE).size();

        // Idea: Half the amount of added/removed cipher suites until we have made a step of 1

        int stepsize = maxUsableCipherSuiteCount - offeredCipherSuites.size();
        int offeredAmount = maxUsableCipherSuiteCount;
        int max = report.getClientSupportedCipherSuites().size();
        int profileIndex = 0;
        while (stepsize > 1) {

            List<CipherSuite> finalOfferedCipherSuites = fillToSuiteAmount(report, offeredAmount);
            LOGGER.trace(
                    "Trying a CH with cipher suites [{}]",
                    finalOfferedCipherSuites.stream()
                            .map(CipherSuite::name)
                            .collect(Collectors.joining(", ")));
            int finalProfileIndex = profileIndex;
            DetailedResult<String> cipherSuiteTestResult =
                    (DetailedResult<String>)
                            executeWithRetries(
                                    () ->
                                            extractCipherSuite(
                                                    finalOfferedCipherSuites,
                                                    finalProfileIndex,
                                                    report));

            if (cipherSuiteTestResult.getSummarizedResult() == TestResults.PARTIALLY) {
                if (offeredAmount > max) {
                    max = offeredAmount;
                    LOGGER.trace("Observed new max of siphersuites accepted ({})", max);
                }
            }
            stepsize = (stepsize + 1) / 2;
            offeredAmount = max + stepsize;

            LOGGER.trace("Performing step to {} cipher suites", offeredAmount);
            if (offeredAmount > maxUsableCipherSuiteCount) {
                LOGGER.trace("Ending max cipher suite count probing");
                break;
            }
            profileIndex++;
        }

        return fillToSuiteAmount(report, max);
    }

    private static List<CipherSuite> fillToSuiteAmount(
            WebRtcPlatformReport report, int totalSuites) {

        if (totalSuites <= 0) {
            throw new IllegalArgumentException("too few total suites asked for: " + totalSuites);
        }

        List<CipherSuite> finalSuites = new ArrayList<>(report.getClientSupportedCipherSuites());
        List<CipherSuite> clientFreeSuites = getTestableCipherSuites();
        clientFreeSuites.removeAll(report.getClientSupportedCipherSuites());
        finalSuites.addAll(clientFreeSuites);
        while (finalSuites.size() > totalSuites) {
            finalSuites.removeLast();
        }
        return finalSuites;
    }

    private List<CipherSuite> getSupportedCipherSuites(
            WebRtcPlatformReport report, List<CipherSuite> offeredCipherSuites) {

        List<CipherSuite> supportedCipherSuites = new ArrayList<>();
        CipherSuite lastCipherSuite = null;
        AtomicInteger index = new AtomicInteger(1000);

        do {
            @SuppressWarnings("unchecked")
            DetailedResult<String> cipherSuiteTestResult =
                    (DetailedResult<String>)
                            executeWithRetries(
                                    () ->
                                            extractCipherSuite(
                                                    offeredCipherSuites, index.get(), report));
            LOGGER.debug("Server chose: " + cipherSuiteTestResult);

            if (cipherSuiteTestResult.getSummarizedResult() != TestResults.PARTIALLY) {
                LOGGER.debug("Server did not choose a cipher suite");
                report.putResult(
                        WebRtcProperties.SERVER_CIPHERSUITE_SCAN_TERMINATION_SYMBOL_SEEN,
                        cipherSuiteTestResult);
                break;
            } else {
                CipherSuite thisCipherSuite =
                        CipherSuite.valueOf(cipherSuiteTestResult.getDetails());
                if (lastCipherSuite == thisCipherSuite) {
                    LOGGER.warn("Server selecting not offered cipher suite: {}", lastCipherSuite);
                    report.putResult(
                            WebRtcProperties.SERVER_CIPHERSUITE_SCAN_TERMINATION_SYMBOL_SEEN,
                            new DetailedResult<>(
                                    TestResults.MAKES_NO_SENSE,
                                    "Server selected cipher suite we did not offer"));
                    break;
                } else {
                    lastCipherSuite = thisCipherSuite;
                    supportedCipherSuites.add(thisCipherSuite);
                    offeredCipherSuites.remove(thisCipherSuite);
                }
            }
            index.incrementAndGet();
        } while (true);
        return supportedCipherSuites;
    }

    private static List<CipherSuite> getTestableCipherSuites() {
        List<CipherSuite> cipherSuites = new ArrayList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isRealCipherSuite()
                    && !suite.isTls13()
                    && suite.getCipherType() != CipherType.STREAM) {
                cipherSuites.add(suite);
            }
        }
        cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        return cipherSuites;
    }

    private TestResult getEnforcesCipherSuiteOrder(
            WebRtcPlatformReport report, List<CipherSuite> testCipherSuites) {
        List<CipherSuite> offeredCipherSuites = new ArrayList<>(testCipherSuites);

        @SuppressWarnings("unchecked")
        DetailedResult<String> firstResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractCipherSuite(offeredCipherSuites, 9999, report));
        LOGGER.debug("Order check first server choice: " + firstResult);
        Collections.reverse(offeredCipherSuites);
        @SuppressWarnings("unchecked")
        DetailedResult<String> secondResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractCipherSuite(offeredCipherSuites, 9998, report));
        LOGGER.debug("Order check second server choice: " + secondResult);

        if (firstResult.getSummarizedResult() != TestResults.PARTIALLY
                || secondResult.getSummarizedResult() != TestResults.PARTIALLY) {
            LOGGER.debug("Could not perform tests, TestResults: {} {}", firstResult, secondResult);
            return new DetailedResult<Serializable>(
                    TestResults.ERROR_DURING_TEST,
                    "" + firstResult.toString() + " " + secondResult.toString());
        }

        CipherSuite firstCipherSuite = CipherSuite.valueOf(firstResult.getDetails());
        CipherSuite secondCipherSuite = CipherSuite.valueOf(secondResult.getDetails());

        if (firstCipherSuite == secondCipherSuite) {
            LOGGER.debug("Server enforces order: {}", firstCipherSuite);
            return new DetailedResult<>(
                    TestResults.TRUE,
                    "Server selected same cipher suite even in reverse order: " + firstCipherSuite);
        } else {
            LOGGER.debug(
                    "Server does not enforce order: {} vs {}", firstCipherSuite, secondCipherSuite);
            return new DetailedResult<>(
                    TestResults.FALSE,
                    "Server selected distinct cipher suites when changing order: "
                            + firstCipherSuite
                            + " vs "
                            + secondCipherSuite);
        }
    }

    /**
     * TODO this is not so nice that its a detailed result...
     *
     * @param offeredCipherSuites
     * @return
     */
    public DetailedResult<String> extractCipherSuite(
            List<CipherSuite> offeredCipherSuites, int index, WebRtcPlatformReport report) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        config.setDefaultClientSupportedCipherSuites(offeredCipherSuites);
        WorkflowTrace trace = createCipherSuiteExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_SUPPORTED_CIPHERSUITES" + index);
        CipherSuite suite =
                connection
                        .getState()
                        .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getSelectedCipherSuite();
        if (suite != null) {
            if (connection.getState().getWorkflowTrace().executedAsPlanned()) {
                functionalCipherSuites.add(suite);
            }
            return new DetailedResult<>(
                    TestResults.PARTIALLY,
                    suite.name()); // We use partially here to indicate that the test is ongoing...
        } else {
            for (ProtocolMessage message : trace.getLastReceivingAction().getReceivedMessages()) {
                if (message instanceof AlertMessage) {
                    LOGGER.debug("Received an Alert message. Found proof.");
                    return new DetailedResult<>(
                            TestResults.TRUE, "Received alert message: " + message.toString());
                }
            }
            if (executionAttemptsExceeded()) {
                return new DetailedResult<>(TestResults.FALSE, "Received no alert. No proof.");
            } else {
                throw new MissingProofException();
            }
        }
    }

    /**
     * Creates a trace that probes a server for supported cipher suites.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     *                           Send     |---ClientHello--->|
     *                       Receive Till |<------SHD--------|
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createCipherSuiteExtractionTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);
        trace.addTlsAction(
                new SendAction(ATTACKER_TO_SERVER_CONNECTION, new ClientHelloMessage(config)));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(
                WebRtcProperties.COMPLETELY_FUNCTIONAL, WebRtcProperties.WANT_TO_TEST_SERVER);
    }
}
