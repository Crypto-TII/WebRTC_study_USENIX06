/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.dtls;

import de.rub.nds.dtlsproxy.action.ForwardServerFlightAction;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.WebrtcExecutionContext;
import de.rub.nds.dtlsproxy.provider.TraceableConnection;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.scanner.core.probe.result.StringResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SelfTestProbe extends DtlsProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    public SelfTestProbe(WebrtcExecutionContext webrtcExecutionContext) {
        super(webrtcExecutionContext);
    }

    @Override
    protected void runChecks(WebRtcPlatformReport report) {

        Boolean isClientStartingUp = null;
        Boolean isServerStartingUp = null;
        try {
            LOGGER.trace("Performing a selftest");
            Config config =
                    TraceUtil.getDefaultConfig(
                            getProxyConfiguration(),
                            CLIENT_TO_ATTACKER_CONNECTION,
                            ATTACKER_TO_SERVER_CONNECTION);

            WorkflowTrace trace = createHelloVerifyRequestTrace(report, config);
            TraceableConnection connection = createConnection(config, trace);
            execute(connection, "HVR_TEST");

            isClientStartingUp = receivedClientHello(trace);
            LOGGER.debug("Client is starting: " + isClientStartingUp);
            isServerStartingUp = receivedHelloVerifyRequest(trace);
            LOGGER.debug("Server is starting: " + isServerStartingUp);

            if (receivedClientHello(trace)) {
                extractInformationFromClientHello(report, connection.getState());
                config =
                        TraceUtil.getFunctionalConfig(
                                getProxyConfiguration(),
                                report,
                                CLIENT_TO_ATTACKER_CONNECTION,
                                ATTACKER_TO_SERVER_CONNECTION);
            }

            if (!isServerStartingUp) {
                trace = createReceiveClientCcsTrace(report, config);
                connection = createConnection(config, trace);
                execute(connection, "SHORT_SELFTEST");
                isServerStartingUp = receivedServerHello(trace);
            }

            if (receivedHelloVerifyRequest(trace)) {
                report.putResult(
                        WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.TRUE);
                report.putResult(
                        WebRtcProperties.HVR_EXAMPLE_COOKIE,
                        new StringResult(
                                WebRtcProperties.HVR_EXAMPLE_COOKIE,
                                ArrayConverter.bytesToHexString(
                                        trace.getLastReceivedMessage(
                                                        HelloVerifyRequestMessage.class)
                                                .getCookie()
                                                .getValue())));
            } else {
                report.putResult(
                        WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST, TestResults.FALSE);
            }
            if (isClientStartingUp && isServerStartingUp) {

                trace = createReceiveClientCcsTrace(report, config);
                connection = createConnection(config, trace);
                execute(connection, "MEDIUM_SELFTEST");

                if (trace.executedAsPlanned()) {
                    report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.TRUE);
                } else {
                    report.putResult(WebRtcProperties.COMPLETELY_FUNCTIONAL, TestResults.PARTIALLY);
                }

                if (WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.CERTIFICATE_REQUEST)) {
                    report.putResult(
                            WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, TestResults.TRUE);
                } else {
                    report.putResult(
                            WebRtcProperties.SERVER_REQUESTS_CERTIFICATE, TestResults.FALSE);
                }

                report.setExampleClientCertificateChain(
                        connection
                                .getState()
                                .getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                                .getClientCertificateChain());

                // Extract some basic information about the connection
                if (receivedServerHello(trace)) {
                    extractInformationFromServerHello(report, connection.getState());
                    extractInformationFromServerCertificate(report, connection.getState());
                }
                if (receivedServerKeyExchange(trace)) {
                    extractInformationFromServerKeyExchange(report, trace, connection.getState());
                }
                if (receivedCertificateRequest(trace)) {
                    extractInformationFromCertificateRequest(report, connection);
                }
                if (trace.executedAsPlanned()) {
                    extractInformationFromClientCertificateVerify(report, connection.getState());
                }
            }
            report.putResult(WebRtcProperties.CLIENT_FUNCTIONAL, isClientStartingUp);
            report.putResult(WebRtcProperties.SERVER_FUNCTIONAL, isServerStartingUp);
        } catch (Exception ex) {
            report.putResult(
                    WebRtcProperties.CLIENT_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, ex.getMessage()));
            report.putResult(
                    WebRtcProperties.COMPLETELY_FUNCTIONAL,
                    new DetailedResult<String>(TestResults.ERROR_DURING_TEST, ex.getMessage()));
            LOGGER.warn("Could not execute test", ex);
            if (ex.getCause() instanceof TimeoutException) {
                LOGGER.trace("Client timeout threshold exceeded. Did not receive ClientHello.");
            }
        }
    }

    private void extractInformationFromCertificateRequest(
            WebRtcPlatformReport report, TraceableConnection connection) {
        report.setServerRequestedSignatureAndHashAlgorithms(
                connection
                        .getState()
                        .getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getServerSupportedSignatureAndHashAlgorithms());
    }

    private boolean receivedCertificateRequest(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(
                trace, HandshakeMessageType.CERTIFICATE_REQUEST);
    }

    private boolean receivedHelloVerifyRequest(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(
                trace, HandshakeMessageType.HELLO_VERIFY_REQUEST);
    }

    private void extractInformationFromServerKeyExchange(
            WebRtcPlatformReport report, WorkflowTrace trace, State state) {
        HandshakeMessage handshakeMessage =
                WorkflowTraceResultUtil.getFirstReceivedMessage(
                        trace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        ServerKeyExchangeMessage skeMessage = (ServerKeyExchangeMessage) handshakeMessage;
        report.setDefaultSignatureLength(skeMessage.getSignature().getValue().length);
        report.setDefaultServerSelectedSignatureAndHashAlgorithm(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getServerSelectedSignatureAndHashAlgorithm());
        report.setDefaultSelectedNamedGroup(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedGroup());
    }

    private void extractInformationFromServerCertificate(WebRtcPlatformReport report, State state) {
        report.setExampleServerCertificateChain(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getServerCertificateChain());
    }

    private void extractInformationFromClientCertificateVerify(
            WebRtcPlatformReport report, State state) {
        report.setDefaultClientSelectedSignatureAndHashAlgorithm(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                        .getClientSelectedSignatureAndHashAlgorithm());
    }

    private void extractInformationFromServerHello(WebRtcPlatformReport report, State state) {

        if (state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                .getProposedExtensions()
                .contains(ExtensionType.USE_SRTP)) {
            report.putResult(WebRtcProperties.SERVER_NEGOTIATES_SRTP, TestResults.TRUE);
        } else {
            report.putResult(WebRtcProperties.SERVER_NEGOTIATES_SRTP, TestResults.FALSE);
        }

        report.setDefaultSelectedCipherSuite(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedCipherSuite());
        report.setDefaultSelectedProtocolVersion(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedProtocolVersion());
        report.setDefaultSelectedCompressionMethod(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedCompressionMethod());
        report.setDefaultSelectedSrtpProtectionProfile(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION)
                        .getSelectedSrtpProtectionProfile());
        report.setNegotiatedExtensions(
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getNegotiatedExtensionSet());

        if (state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedProtocolVersion()
                == ProtocolVersion.DTLS10) {
            report.putResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_0, TestResults.TRUE);
        }
        if (state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getSelectedProtocolVersion()
                == ProtocolVersion.DTLS12) {
            report.putResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_2, TestResults.TRUE);
        }

        report.putResult(
                WebRtcProperties.SERVER_ISSUES_SESSION_IDS,
                state.getTlsContext(ATTACKER_TO_SERVER_CONNECTION).getServerSessionId() != null);
    }

    private void extractInformationFromClientHello(WebRtcPlatformReport report, State state) {

        if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                .getProposedExtensions()
                .contains(ExtensionType.SERVER_NAME_INDICATION)) {
            report.setClientSNIEntryList(
                    state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getClientSNIEntryList());
            report.putResult(WebRtcProperties.CLIENT_SENDS_SNI, TestResults.TRUE);
        } else {
            report.putResult(WebRtcProperties.CLIENT_SENDS_SNI, TestResults.FALSE);
        }

        if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                .getProposedExtensions()
                .contains(ExtensionType.SESSION_TICKET)) {
            report.putResult(WebRtcProperties.CLIENT_SUPPORTS_SESSION_TICKETS, TestResults.TRUE);
        } else {
            report.putResult(WebRtcProperties.CLIENT_SUPPORTS_SESSION_TICKETS, TestResults.FALSE);
        }

        if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                .getProposedExtensions()
                .contains(ExtensionType.USE_SRTP)) {
            report.putResult(WebRtcProperties.CLIENT_NEGOTIATES_SRTP, TestResults.TRUE);
        } else {
            report.putResult(WebRtcProperties.CLIENT_NEGOTIATES_SRTP, TestResults.FALSE);
        }

        report.setClientSupportedCipherSuites(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                        .getClientSupportedCipherSuites());
        report.setClientSupportedCompressionMethods(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                        .getClientSupportedCompressions());
        report.setClientSupportedExtensions(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getProposedExtensions());
        report.setClientSupportedProtectionProfiles(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                        .getClientSupportedSrtpProtectionProfiles());
        report.setClientSupportedNamedGroups(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getClientNamedGroupsList());
        report.putResult(
                WebRtcProperties.CLIENT_SENDS_SRTP_MKI,
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                                        .getSecureRealTimeProtocolMasterKeyIdentifier()
                                != null
                        && state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                                        .getSecureRealTimeProtocolMasterKeyIdentifier()
                                        .length
                                != 0);
        report.putResult(
                WebRtcProperties.EXAMPLE_SRTP_MKI_VALUE,
                new StringResult(
                        WebRtcProperties.EXAMPLE_SRTP_MKI_VALUE,
                        ArrayConverter.bytesToHexString(
                                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                                        .getSecureRealTimeProtocolMasterKeyIdentifier())));

        report.setClientSupportedSignatureAndHashAlgorithms(
                state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                        .getClientSupportedSignatureAndHashAlgorithms());
        if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION)
                .getProposedExtensions()
                .contains(ExtensionType.SUPPORTED_VERSIONS)) {
            // Only DTLS 1.3 clients support this extension - so no need to check contents for now
            report.putResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_3, TestResults.TRUE);
        } else {
            report.putResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_3, TestResults.FALSE);
            if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getHighestClientProtocolVersion()
                    == ProtocolVersion.DTLS10) {
                report.putResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_0, TestResults.TRUE);
            }
            if (state.getTlsContext(CLIENT_TO_ATTACKER_CONNECTION).getHighestClientProtocolVersion()
                    == ProtocolVersion.DTLS12) {
                report.putResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_2, TestResults.TRUE);
            }
        }
    }

    private boolean receivedServerKeyExchange(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(
                trace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    private boolean receivedServerHello(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.SERVER_HELLO);
    }

    private boolean receivedClientHello(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.CLIENT_HELLO);
    }

    /**
     * Creates a trace that forwards messages and then tries to receive a CCS message from the
     * client, which should give enough indication that that everything is working as expected.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<---SH Flight-----|    Forward    |<---SH Flight-----|
     * |--------CCS------>|  Receive Till
     * </pre>
     *
     * @param report
     * @param config
     * @return
     */
    private WorkflowTrace createReceiveClientCcsTrace(WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace;
        trace =
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
                new ForwardServerFlightAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, false, true));
        trace.addTlsAction(
                new ReceiveTillAction(
                        CLIENT_TO_ATTACKER_CONNECTION, new ChangeCipherSpecMessage()));
        return trace;
    }

    private WorkflowTrace createHelloVerifyRequestTrace(
            WebRtcPlatformReport report, Config config) {
        WorkflowTrace trace;
        trace =
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
                new ReceiveAction(ATTACKER_TO_SERVER_CONNECTION, new HelloVerifyRequestMessage()));
        return trace;
    }

    @Override
    protected List<WebRtcProperties> getRequiredProperties() {
        return List.of(WebRtcProperties.PROVIDER_FUNCTIONAL);
    }
}
