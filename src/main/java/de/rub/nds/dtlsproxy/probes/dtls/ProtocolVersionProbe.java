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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopBufferedMessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProtocolVersionProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    // source: wolfssl c script
    private static final byte[] DTLS_1_3_CLIENT_HELLO =
            ArrayConverter.hexStringToByteArray(
                    "010000effefdafbb523145022a040d51318ef625a6846788d76f93791f29038529bb37ff16b500000036130113021303c02cc02bc030c02f009f009ecca9cca8ccaac027c023c028c024c00ac009c014c013006b006700390033cc14cc13cc150100008f002d000302000100330047004500170041048b189b5109e36238fcc35b47207e99b3a59ab8acd275202013a5c528939fe10806c21adaa370129766e743cc1e6f6bed1f04a636e8265ceec449f862e52e9b45002b000302fefc000d001e001c06030503040308070806080b0805080a080408090601050104010301000a000c000a0019001800170015010000160000");

    public ProtocolVersionProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {
        if (report.getResult(WebRtcProperties.WANT_TO_TEST_CLIENT) == TestResults.TRUE) {
            if (report.getResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_0)
                    == TestResults.NOT_TESTED_YET) {
                report.putResult(
                        WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_0,
                        executeWithRetries(() -> getClientVersion(report, ProtocolVersion.DTLS10)));
            }
            if (report.getResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_2)
                    == TestResults.NOT_TESTED_YET) {
                report.putResult(
                        WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_2,
                        executeWithRetries(() -> getClientVersion(report, ProtocolVersion.DTLS12)));
            }
        }
        // We are not testing DTLS 1.3 for the client as we can see support in the CH
        // during the selftest
        if (report.getResult(WebRtcProperties.WANT_TO_TEST_SERVER) == TestResults.TRUE) {
            if (report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_0)
                    == TestResults.NOT_TESTED_YET) {
                report.putResult(
                        WebRtcProperties.SERVER_SUPPORTS_DTLS_1_0,
                        executeWithRetries(() -> getServerVersion(report, ProtocolVersion.DTLS10)));
            }

            if (report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_2)
                    == TestResults.NOT_TESTED_YET) {
                report.putResult(
                        WebRtcProperties.SERVER_SUPPORTS_DTLS_1_2,
                        executeWithRetries(() -> getServerVersion(report, ProtocolVersion.DTLS12)));
            }
            if (report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_3)
                    == TestResults.NOT_TESTED_YET) {
                report.putResult(
                        WebRtcProperties.SERVER_SUPPORTS_DTLS_1_3,
                        executeWithRetries(() -> getServerVersion(report, ProtocolVersion.DTLS13)));
            }
        }
    }

    private TestResult getClientVersion(WebRtcPlatformReport report, ProtocolVersion version) {
        LOGGER.info("Testing client version: {}", version);
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        config.setDefaultSelectedProtocolVersion(version);
        config.setSupportedVersions(version);
        config.setHighestProtocolVersion(version);
        if (version == ProtocolVersion.DTLS10) {
            // If the version we are testing is DTLS 1.0, we need to remove more modern cipher
            // suites from the config
            CipherSuite selectedCipherSuite = null;
            for (CipherSuite suite : report.getClientSupportedCipherSuites()) {
                if (!suite.isTls13()
                        && suite.isRealCipherSuite()
                        && suite.getCipherType() != CipherType.STREAM
                        && AlgorithmResolver.getMacAlgorithm(version, suite).getMacLength()
                                <= 160) {
                    selectedCipherSuite = suite;
                }
            }
            config.setDefaultSelectedCipherSuite(selectedCipherSuite);
            config.setDefaultServerSupportedCipherSuites(selectedCipherSuite);
        }
        WorkflowTrace trace = createClientVersionExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);
        execute(connection, "CLIENT_VERSION_" + version.name());
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so the client accepted our selected version
            return TestResults.TRUE;

        } else {
            ProtocolMessage lastMessage;
            if (trace.getLastReceivingAction().getReceivedMessages().isEmpty()) {
                lastMessage = null;
            } else {
                lastMessage =
                        trace.getLastReceivingAction()
                                .getReceivedMessages()
                                .get(
                                        trace.getLastReceivingAction().getReceivedMessages().size()
                                                - 1);
            }

            if (lastMessage instanceof AlertMessage) {
                LOGGER.debug("Received an Alert message. Found proof.");
                return new DetailedResult<String>(
                        TestResults.FALSE,
                        "Received alert message: " + lastMessage.toCompactString());
            }

            if (executionAttemptsExceeded()) {
                return new DetailedResult<String>(TestResults.FALSE, "No proof");
            } else {
                throw new MissingProofException();
            }
        }
    }

    private TestResult getServerVersion(WebRtcPlatformReport report, ProtocolVersion version) {
        LOGGER.info("Testing server version: {}", version);
        Config config =
                TraceUtil.getFunctionalConfig(
                        getProxyConfiguration(),
                        report,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION);
        if (version == ProtocolVersion.DTLS13) {
            config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
            config.setSupportedVersions(ProtocolVersion.DTLS12);
            config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        } else {
            config.setDefaultSelectedProtocolVersion(version);
            config.setSupportedVersions(version);
            config.setHighestProtocolVersion(version);
        }
        WorkflowTrace trace = createServerVersionExtractionTrace(report, config);
        TraceableConnection connection = createConnection(config, trace);

        // if the version we are testing is DTLS 1.3, we must overwrite our ClientHello as
        // TLS-Attacker
        // does not support DTLS 1.3 at the time. Furthermore DTLS1.3 appears as 1.2 in the outer
        // version field and is
        // negotiated by presenting 1.3 as a supported version in the "supported versions" extension
        if (version == ProtocolVersion.DTLS13) {
            HandshakeMessage clientHello =
                    WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                            trace, HandshakeMessageType.CLIENT_HELLO);
            clientHello.setCompleteResultingMessage(Modifiable.explicit(DTLS_1_3_CLIENT_HELLO));
        }
        if (version == ProtocolVersion.DTLS10) {
            // If the version we are testing is DTLS 1.0, we need to remove more modern cipher
            // suites from the config
            List<CipherSuite> supportedCipherSuites = new ArrayList<>();
            for (CipherSuite suite : CipherSuite.values()) {
                if (suite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                    supportedCipherSuites.add(suite);
                } else if (!suite.isTls13()
                        && suite.isRealCipherSuite()
                        && suite.getCipherType() != CipherType.STREAM
                        && AlgorithmResolver.getMacAlgorithm(version, suite).getMacLength()
                                <= 160) {
                    supportedCipherSuites.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(supportedCipherSuites);
        }
        execute(connection, "SERVER_VERSION_" + version.name());
        if (!trace.allActionsExecuted()) {
            throw new RuntimeException("Not all actions executed: " + trace.toString());
        } else if (trace.executedAsPlanned()) {
            // Handshake finished as planned, so server chose a version
            if (connection
                            .getState()
                            .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                            .getSelectedProtocolVersion()
                    == version) {
                LOGGER.info("Server supports: {}", version);
                return TestResults.TRUE;
            } else {
                LOGGER.info(
                        "Server chose: {}",
                        connection
                                .getState()
                                .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                                .getSelectedProtocolVersion());
                return TestResults.FALSE;
            }
        } else {
            ProtocolMessage lastMessage;
            if (trace.getLastReceivingAction().getReceivedMessages().isEmpty()) {
                lastMessage = null;
            } else {
                lastMessage =
                        trace.getLastReceivingAction()
                                .getReceivedMessages()
                                .get(
                                        trace.getLastReceivingAction().getReceivedMessages().size()
                                                - 1);
            }

            if (lastMessage instanceof AlertMessage) {
                LOGGER.debug("Received an Alert message. Found proof.");
                return new DetailedResult<String>(
                        TestResults.FALSE,
                        "Received alert message: " + lastMessage.toCompactString());
            }

            if (executionAttemptsExceeded()) {
                return new DetailedResult<String>(TestResults.FALSE, "No proof");
            } else {
                throw new MissingProofException();
            }
        }
    }

    /**
     * Create a trace that will send a different Certificate than expected. Depending on the cipher
     * suite, the SKE message will also me adjusted.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|   Forward      |---------CH------>|
     *                        Buffer Till  |<--------SHD------|
     *                    |<-Copy Buffers<-|
     *                    |<- Copy Random<-|
     * |<--ServerHello----|    Send
     *                    |     Pop        |
     * |<--Certificate----|  Pop and Send  |
     * |<-------SKE*------|  Pop and Send  |
     * |<-------CR*-------|     Send          // We send the CR and SHD message ourselfs
     * |<-------SHD-------|     Send          // because CR looks different in differnt versions
     * |ChangeCipherSpec->| Receive Till
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test client supported versions
     */
    private WorkflowTrace createClientVersionExtractionTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        trace.addTlsAction(
                new ForwardMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ClientHelloMessage()));
        trace.addTlsAction(
                new BufferedReceiveTillAction(
                        ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new CopyBufferedMessagesAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new CopyServerRandomAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new PopBufferedMessageAction(
                        CLIENT_TO_ATTACKER_CONNECTION)); // ServerHello //REMOVE
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloMessage(config)));
        trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // Certificate
        if (report.getDefaultSelectedCipherSuite().isEphemeral()) {
            trace.addTlsAction(new PopAndSendAction(CLIENT_TO_ATTACKER_CONNECTION)); // SKE
        }
        if (report.getResult(WebRtcProperties.SERVER_REQUESTS_CERTIFICATE) == TestResults.TRUE) {
            trace.addTlsAction(
                    new SendAction(
                            CLIENT_TO_ATTACKER_CONNECTION,
                            new CertificateRequestMessage(config))); // CR
        }
        trace.addTlsAction(
                new SendAction(CLIENT_TO_ATTACKER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    /**
     * Create a trace that will send a CH to the server to
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|   Receive
     *                        Send         |---------CH------->|
     *                    |   Receive Till |<--------SH--------|
     *
     * </pre>
     *
     * @param report The report to create the Mitm Base-trace from
     * @param config The configuration file that should be used to create new messages
     * @return A WorkflowTrace that can be used to test server supported versions
     */
    private WorkflowTrace createServerVersionExtractionTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        trace.addTlsAction(
                new ReceiveAction(CLIENT_TO_ATTACKER_CONNECTION, new ClientHelloMessage()));
        trace.addTlsAction(
                new SendAction(ATTACKER_TO_SERVER_CONNECTION, new ClientHelloMessage(config)));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloMessage()));
        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(WebRtcProperties.COMPLETELY_FUNCTIONAL);
    }
}
