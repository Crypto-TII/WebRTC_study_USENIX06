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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamedGroupsProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerNamedGroupsProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        LOGGER.info("Testing which named groups are supported by the server (SKE)");
        List<NamedGroup> offeredNamedGroup = new ArrayList<>();

        for (NamedGroup namedGroup : NamedGroup.values()) {
            if (!namedGroup.isGrease()) {
                offeredNamedGroup.add(namedGroup);
            }
        }
        // If the server is using an ECDSA certificate we move it to the last position to
        // avoid the handshake breaking if we do not advertise the curve
        X509CertificateChain serverChain = report.getExampleServerCertificateChain();
        if (serverChain.getLeaf().getCertificateKeyType() == X509PublicKeyType.ECDH_ECDSA) {
            LOGGER.info("Server is using ECDSA certificate, moving curve to last position");
            NamedGroup curve = NamedGroup.convert(serverChain.getLeaf().getEllipticCurve());
            offeredNamedGroup.remove(curve);
            offeredNamedGroup.add(curve);
        }

        try {
            List<NamedGroup> supportedNamedGroups =
                    getSupportedNamedGroups(report, offeredNamedGroup);
            report.setServerSupportedNamedGroups(supportedNamedGroups);
            report.putResult(
                    WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_NAMED_GROUPS,
                    getEnforcesNamedGroupOrder(report));
        } catch (Exception e) {
            LOGGER.warn("Could not perform test", e);
        }
    }

    private List<NamedGroup> getSupportedNamedGroups(
            WebRtcPlatformReport report, List<NamedGroup> offeredNamedGroups) {

        List<NamedGroup> supportedNamedGroups = new ArrayList<>();
        NamedGroup lastNamedGroup = null;
        AtomicInteger index = new AtomicInteger(0);

        do {
            @SuppressWarnings("unchecked")
            DetailedResult<String> namedGroupResult =
                    (DetailedResult<String>)
                            executeWithRetries(
                                    () ->
                                            extractNamedGroup(
                                                    offeredNamedGroups, index.get(), report));
            LOGGER.debug("Server chose: " + namedGroupResult);

            if (namedGroupResult.getSummarizedResult() != TestResults.PARTIALLY) {
                LOGGER.debug("Server did not choose a named group");
                report.putResult(
                        WebRtcProperties.SERVER_NAMED_GROUP_SCAN_TERMINATION_SYMBOL_SEEN,
                        namedGroupResult);
                break;
            } else {
                NamedGroup thisNamedGroup = NamedGroup.valueOf(namedGroupResult.getDetails());
                if (lastNamedGroup == thisNamedGroup) {
                    LOGGER.warn("Server selecting not offered named group: {}", lastNamedGroup);
                    report.putResult(
                            WebRtcProperties.SERVER_NAMED_GROUP_SCAN_TERMINATION_SYMBOL_SEEN,
                            new DetailedResult<>(
                                    TestResults.MAKES_NO_SENSE,
                                    "Server selected named group we did not offer"));
                    break;
                } else {
                    lastNamedGroup = thisNamedGroup;
                    supportedNamedGroups.add(thisNamedGroup);
                    offeredNamedGroups.remove(thisNamedGroup);
                }
            }
            index.incrementAndGet();
        } while (true);
        return supportedNamedGroups;
    }

    private TestResult getEnforcesNamedGroupOrder(WebRtcPlatformReport report) {
        List<NamedGroup> offeredNamedGroup = new ArrayList<>();
        for (NamedGroup namedGroup : NamedGroup.values()) {
            offeredNamedGroup.add(namedGroup);
        }

        @SuppressWarnings("unchecked")
        DetailedResult<String> firstResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractNamedGroup(offeredNamedGroup, 9999, report));
        LOGGER.debug("Server chose: " + firstResult);
        Collections.reverse(offeredNamedGroup);
        @SuppressWarnings("unchecked")
        DetailedResult<String> secondResult =
                (DetailedResult<String>)
                        executeWithRetries(
                                () -> extractNamedGroup(offeredNamedGroup, 9998, report));

        if (firstResult.getSummarizedResult() != TestResults.PARTIALLY
                || secondResult.getSummarizedResult() != TestResults.PARTIALLY) {
            LOGGER.debug("Could not perform tests, TestResults: {} {}", firstResult, secondResult);
            return new DetailedResult<Serializable>(
                    TestResults.ERROR_DURING_TEST,
                    "" + firstResult.toString() + " " + secondResult.toString());
        }

        NamedGroup firstNamedGroup = NamedGroup.valueOf(firstResult.getDetails());
        NamedGroup secondNamedGroup = NamedGroup.valueOf(secondResult.getDetails());

        if (firstNamedGroup == secondNamedGroup) {
            LOGGER.debug("Server enforces order: {}", firstNamedGroup);
            return new DetailedResult<>(
                    TestResults.TRUE,
                    "Server selected same named group even in reverse order: " + firstNamedGroup);
        } else {
            LOGGER.debug(
                    "Server does not enforce order: {} vs {}", firstNamedGroup, secondNamedGroup);
            return new DetailedResult<>(
                    TestResults.FALSE,
                    "Server selected distinct named group when changing order: "
                            + firstNamedGroup
                            + " vs "
                            + secondNamedGroup);
        }
    }

    /**
     * TODO this is not so nice that its a detailed result...
     *
     * @param offeredCipherSuites
     * @return
     */
    public DetailedResult<String> extractNamedGroup(
            List<NamedGroup> offeredNamedGroups, int index, WebRtcPlatformReport report) {
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        List<CipherSuite> offeredCipherSuites = new ArrayList<>();
        for (CipherSuite suite : config.getDefaultServerSupportedCipherSuites()) {
            if (suite.isEphemeral()
                    && !suite.isTls13()
                    && suite.isRealCipherSuite()
                    && suite.getCipherType() != CipherType.STREAM) {
                offeredCipherSuites.add(suite);
            }
        }
        offeredCipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setAddSRTPExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setDefaultClientSupportedCipherSuites(offeredCipherSuites);
        config.setDefaultClientNamedGroups(offeredNamedGroups);
        WorkflowTrace trace = createNamedGroupExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "SERVER_SUPPORTED_GROUPS_" + index);
        NamedGroup namedGroup =
                connection
                        .getState()
                        .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getSelectedGroup();
        if (namedGroup != null) {
            return new DetailedResult<String>(
                    TestResults.PARTIALLY,
                    namedGroup.name()); // We use partially here to indicate that the test is
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
    private WorkflowTrace createNamedGroupExtractionTrace(
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
