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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSkeSignatureAndHashAlgorithmsProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSkeSignatureAndHashAlgorithmsProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        LOGGER.info(
                "Testing which signature and hash algorithms are supported by the server (SKE)");
        List<SignatureAndHashAlgorithm> offeredSignatureAndHashAlgorithm = new ArrayList<>();
        for (SignatureAndHashAlgorithm signatureAndHashAlgorithm :
                SignatureAndHashAlgorithm.values()) {
            if (!signatureAndHashAlgorithm.isGrease()) {
                offeredSignatureAndHashAlgorithm.add(signatureAndHashAlgorithm);
            }
        }

        try {
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms =
                    getSupportedSignatureAndHashAlgorithms(
                            report, offeredSignatureAndHashAlgorithm);

            if (supportedSignatureAndHashAlgorithms.isEmpty()) {
                LOGGER.debug(
                        "Server did not respond to our signature and hash algorithms, trying again with reduced test set");
                // Fallback to reduced, rotating test set
                supportedSignatureAndHashAlgorithms =
                        getSupportedSignatureAndHashAlgorithmsFallback(
                                report, offeredSignatureAndHashAlgorithm);
            }

            if (supportedSignatureAndHashAlgorithms.isEmpty()) {
                LOGGER.warn("Could not find supported signature and hash algorithms");
            }

            report.setServerSupportedSignatureAndHashAlgorithms(
                    supportedSignatureAndHashAlgorithms);
            report.putResult(
                    WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_SKE_SIG_HASH_ALGORITHMS,
                    getEnforcesSignAndHashAlgorithmOrder(report));
        } catch (Exception e) {
            LOGGER.warn("Could not extract algorithms", e);
        }
    }

    private TestResult getEnforcesSignAndHashAlgorithmOrder(WebRtcPlatformReport report) {
        List<SignatureAndHashAlgorithm> offeredAlgorithms = new ArrayList<>();
        for (SignatureAndHashAlgorithm profiles : SignatureAndHashAlgorithm.values()) {
            offeredAlgorithms.add(profiles);
        }

        @SuppressWarnings("unchecked")
        DetailedResult<String> firstResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () ->
                                        extractSignatureAndHashAlgorithm(
                                                offeredAlgorithms, 9999, report));
        LOGGER.debug("Server chose: " + firstResult);
        Collections.reverse(offeredAlgorithms);
        @SuppressWarnings("unchecked")
        DetailedResult<String> secondResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () ->
                                        extractSignatureAndHashAlgorithm(
                                                offeredAlgorithms, 9998, report));

        if (firstResult.getSummarizedResult() != TestResults.PARTIALLY
                || secondResult.getSummarizedResult() != TestResults.PARTIALLY) {
            LOGGER.debug("Could not perform tests, TestResults: {} {}", firstResult, secondResult);
            return new DetailedResult<Serializable>(
                    TestResults.ERROR_DURING_TEST,
                    "" + firstResult.toString() + " " + secondResult.toString());
        }

        SignatureAndHashAlgorithm firstAlgorithm =
                SignatureAndHashAlgorithm.valueOf(firstResult.getDetails());
        SignatureAndHashAlgorithm secondAlgorithm =
                SignatureAndHashAlgorithm.valueOf(secondResult.getDetails());

        if (firstAlgorithm == secondAlgorithm) {
            LOGGER.debug("Server enforces order: {}", firstAlgorithm);
            return new DetailedResult<>(
                    TestResults.TRUE,
                    "Server selected same SignatureAndHashAlgorithm even in reverse order: "
                            + firstAlgorithm);
        } else {
            LOGGER.debug(
                    "Server does not enforce order: {} vs {}", firstAlgorithm, secondAlgorithm);
            return new DetailedResult<>(
                    TestResults.FALSE,
                    "Server selected distinct SignatureAndHashAlgorithm when changing order: "
                            + firstAlgorithm
                            + " vs "
                            + secondAlgorithm);
        }
    }

    /**
     * Tries to learn all algorithms the server supports while never offering more algorithms than
     * the size of the list originally sent by the real client.
     *
     * <p>Strategy: 1. Start with the exact list the client sent in the first DTLS handshake. 2.
     * Determine which of those algorithms the server is willing to use (see {@link
     * #getSupportedSignatureAndHashAlgorithms(WebRtcPlatformReport, List)}). 3. Remove the
     * algorithms we have just tested (supported **and** unsupported) from the global work-list and
     * fill the now freed slots with yet untested candidates – keeping the overall list length
     * constant. 4. Repeat until every algorithm from {@code offeredSignatureAndHashAlgorithms} has
     * been offered once.
     */
    private List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsFallback(
            WebRtcPlatformReport report,
            List<SignatureAndHashAlgorithm> offeredSignatureAndHashAlgorithms) {

        // Size of the list that was sent by the original client – this is our upper bound
        List<SignatureAndHashAlgorithm> clientOffered =
                report.getClientSupportedSignatureAndHashAlgorithms();
        int maxListSize =
                (clientOffered != null && !clientOffered.isEmpty())
                        ? clientOffered.size()
                        : offeredSignatureAndHashAlgorithms.size();

        // Work-list with every algorithm we still have to test
        List<SignatureAndHashAlgorithm> remainingToTest =
                new ArrayList<>(new LinkedHashSet<>(offeredSignatureAndHashAlgorithms));

        List<SignatureAndHashAlgorithm> supported = new ArrayList<>();
        boolean firstIteration = true;

        while (!remainingToTest.isEmpty()) {
            // Build the list that will be sent in the next ClientHello
            List<SignatureAndHashAlgorithm> toOffer = new ArrayList<>(maxListSize);

            if (firstIteration && clientOffered != null) {
                // Offer exactly what the real client offered in its first flight
                for (SignatureAndHashAlgorithm alg : clientOffered) {
                    if (remainingToTest.contains(alg) && toOffer.size() < maxListSize) {
                        toOffer.add(alg);
                    }
                }
                firstIteration = false;
            }

            // Fill the not-yet-used slots with still untested algorithms
            for (SignatureAndHashAlgorithm alg : remainingToTest) {
                if (toOffer.size() >= maxListSize) {
                    break;
                }
                if (!toOffer.contains(alg)) {
                    toOffer.add(alg);
                }
            }

            if (toOffer.isEmpty()) {
                // Nothing left we could offer
                break;
            }

            LOGGER.debug("Fallback probing with subset: {}", toOffer);

            // Determine which of the offered algorithms the server actually supports
            List<SignatureAndHashAlgorithm> supportedThisRound =
                    getSupportedSignatureAndHashAlgorithms(report, new ArrayList<>(toOffer));
            supported.addAll(supportedThisRound);

            // Every algorithm we just offered has now been tested – supported or not
            remainingToTest.removeAll(toOffer);
        }

        return supported;
    }

    private List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms(
            WebRtcPlatformReport report,
            List<SignatureAndHashAlgorithm> offeredSignatureAndHashAlgorithms) {

        List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = new ArrayList<>();
        SignatureAndHashAlgorithm lastSignatureAndHashAlgorithm = null;
        AtomicInteger index = new AtomicInteger(0);

        do {
            @SuppressWarnings("unchecked")
            DetailedResult<String> signatureAndHashAlgorithmResult =
                    (DetailedResult<String>)
                            executeWithRetries(
                                    () ->
                                            extractSignatureAndHashAlgorithm(
                                                    offeredSignatureAndHashAlgorithms,
                                                    index.get(),
                                                    report));
            LOGGER.debug("Server chose: " + signatureAndHashAlgorithmResult);

            if (signatureAndHashAlgorithmResult.getSummarizedResult() != TestResults.PARTIALLY) {
                LOGGER.debug("Server did not choose a signature and hash algorithm");
                report.putResult(
                        WebRtcProperties
                                .SERVER_SIGNATURE_AND_HASH_ALGORITHM_SCAN_TERMINATION_SYMBOL_SEEN,
                        signatureAndHashAlgorithmResult);
                break;
            } else {
                SignatureAndHashAlgorithm thisSignatureAndHashAlgorithm =
                        SignatureAndHashAlgorithm.valueOf(
                                signatureAndHashAlgorithmResult.getDetails());
                if (lastSignatureAndHashAlgorithm == thisSignatureAndHashAlgorithm) {
                    LOGGER.warn(
                            "Server selecting not offered signature and hash algorithm: {}",
                            lastSignatureAndHashAlgorithm);
                    report.putResult(
                            WebRtcProperties
                                    .SERVER_SIGNATURE_AND_HASH_ALGORITHM_SCAN_TERMINATION_SYMBOL_SEEN,
                            new DetailedResult<>(
                                    TestResults.MAKES_NO_SENSE,
                                    "Server selected signature and hash algorithm we did not offer"));
                    break;
                } else {
                    lastSignatureAndHashAlgorithm = thisSignatureAndHashAlgorithm;
                    supportedSignatureAndHashAlgorithms.add(thisSignatureAndHashAlgorithm);
                    offeredSignatureAndHashAlgorithms.remove(thisSignatureAndHashAlgorithm);
                }
            }
            index.incrementAndGet();
        } while (true);
        return supportedSignatureAndHashAlgorithms;
    }

    /**
     * TODO this is not so nice that its a detailed result...
     *
     * @return
     */
    public DetailedResult<String> extractSignatureAndHashAlgorithm(
            List<SignatureAndHashAlgorithm> offeredSignatureAndHashAlgorithms,
            int index,
            WebRtcPlatformReport report) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        List<CipherSuite> offeredCipherSuites = new ArrayList<>();
        for (CipherSuite suite : config.getDefaultServerSupportedCipherSuites()) {
            if (suite.isEphemeral() && suite.isRealCipherSuite() && !suite.isTls13()) {
                offeredCipherSuites.add(suite);
            }
        }
        offeredCipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setAddSRTPExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setDefaultClientSupportedCipherSuites(offeredCipherSuites);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                offeredSignatureAndHashAlgorithms);
        WorkflowTrace trace = createSignatureAndHashAlgorithmExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_SUPPORTED_SIG_HASH_ALGOS_" + index);
        SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                connection
                        .getState()
                        .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getServerSelectedSignatureAndHashAlgorithm();
        if (signatureAndHashAlgorithm != null) {
            return new DetailedResult<String>(
                    TestResults.PARTIALLY,
                    signatureAndHashAlgorithm
                            .name()); // We use partially here to indicate that the test is
            // ongoing...
        } else {
            for (ProtocolMessage message : trace.getLastReceivingAction().getReceivedMessages()) {
                if (message instanceof AlertMessage) {
                    LOGGER.debug("Received an Alert message. Found proof.");
                    return new DetailedResult<String>(
                            TestResults.TRUE, "Received alert message: " + message.toString());
                }
            }
            if (executionAttemptsExceeded()) {
                return new DetailedResult<String>(
                        TestResults.FALSE, "Received no alert. No proof.");
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
    private WorkflowTrace createSignatureAndHashAlgorithmExtractionTrace(
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
