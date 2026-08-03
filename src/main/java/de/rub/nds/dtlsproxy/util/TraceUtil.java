/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TraceUtil {

    private static final int CONNECTION_TIMEOUT = 120000;

    private static final Logger LOGGER = LogManager.getLogger();

    private TraceUtil() {}

    public static WorkflowTrace createTrace(Config config) {
        return new WorkflowTrace(createConnectionList(config));
    }

    public static Config getDefaultConfig(
            ProxyConfiguration proxyConfiguration,
            String clientToAttackerAlias,
            String attackerToServerAlias) {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.DTLS);
        config.setIndividualTransportPacketsForFragments(true);
        // Host and IP will be ignored
        InboundConnection serverConnection =
                new InboundConnection(
                        clientToAttackerAlias,
                        proxyConfiguration.getLocalServerPort(),
                        "127.0.0.1");
        serverConnection.setTimeout((int) proxyConfiguration.getTimeout());
        serverConnection.setConnectionTimeout(CONNECTION_TIMEOUT);
        serverConnection.setTransportHandlerType(TransportHandlerType.UDP);
        // Host and IP will be ignored
        OutboundConnection clientConnection =
                new OutboundConnection(attackerToServerAlias, 0, "127.0.0.1");
        clientConnection.setTransportHandlerType(TransportHandlerType.UDP);
        clientConnection.setConnectionTimeout(CONNECTION_TIMEOUT);
        clientConnection.setTimeout((int) proxyConfiguration.getTimeout());

        config.setDefaultServerConnection(serverConnection);
        config.setDefaultClientConnection(clientConnection);
        List<CipherSuite> suites = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isRealCipherSuite()
                    && !suite.isTls13()
                    && suite.getCipherType() != CipherType.STREAM) {
                suites.add(suite);
            }
        }
        suites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        config.setInitialRecordVersion(ProtocolVersion.DTLS10);
        config.setIgnoreRetransmittedCssInDtls(true);
        config.setDefaultRunningMode(RunningModeType.MITM);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_10);
        config.setDefaultMaxRecordData(1300);
        config.setDtlsMaximumFragmentLength(1300);
        config.setUseFreshRandom(false);
        config.setAddSRTPExtension(true);
        config.setAddSessionTicketTLSExtension(false);
        config.setReorderReceivedDtlsRecords(true);
        config.setDefaultSelectedSrtpProtectionProfile(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
        config.setClientSupportedSrtpProtectionProfiles(List.of(SrtpProtectionProfile.values()));
        config.setClientCertificateTypes(
                ClientCertificateType.ECDSA_SIGN,
                ClientCertificateType.RSA_SIGN,
                ClientCertificateType.DSS_SIGN);

        config.setPreserveMessageRecordRelation(true);
        config.setFinishWithCloseNotify(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setMaxUDPRetransmissions(3);
        return config;
    }

    public static Config applyRtpConfig(Config config) {
        config.setFinishWithCloseNotify(false);
        config.setAddSRTPExtension(true);
        config.setClientSupportedSrtpProtectionProfiles(
                Collections.singletonList(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80));
        config.setDefaultSelectedSrtpProtectionProfile(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
        return config;
    }

    public static Config getFunctionalConfig(
            ProxyConfiguration proxyConfiguration,
            WebRtcPlatformReport report,
            String clientToAttackerAlias,
            String attackerToServerAlias) {
        Config config =
                getDefaultConfig(proxyConfiguration, clientToAttackerAlias, attackerToServerAlias);
        if (report.getClientSupportedSignatureAndHashAlgorithms() != null) {
            config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                    report.getClientSupportedSignatureAndHashAlgorithms());
        }
        if (report.getFunctionalServerSupportedCipherSuites() != null) {
            filterClientCipherSuitesForFunctional(config, report);
            filterServerCipherSuitesForFunctional(config, report);
        } else {
            LOGGER.trace("Not specifying supported cipher suites");
        }
        if (report.getDefaultSelectedCipherSuite() != null) {
            config.setDefaultSelectedCipherSuite(report.getDefaultSelectedCipherSuite());
            LOGGER.trace(
                    "setting default cipher suites: {}",
                    report.getDefaultSelectedCipherSuite().name());
        } else {
            LOGGER.trace("Not specifying default cipher suite");
        }

        // apply session ticket settings
        if (report.getResult(WebRtcProperties.CLIENT_SUPPORTS_SESSION_TICKETS)
                == TestResults.TRUE) {
            config.setAddSessionTicketTLSExtension(true);
        } else {
            config.setAddSessionTicketTLSExtension(false);
        }
        if (report.getResult(WebRtcProperties.CLIENT_NEGOTIATES_SRTP) == TestResults.TRUE) {
            config.setAddSRTPExtension(true);
        } else {
            config.setAddSRTPExtension(false);
        }
        if (report.getResult(WebRtcProperties.CLIENT_SENDS_SNI) == TestResults.TRUE) {
            config.setAddServerNameIndicationExtension(true);
            config.setDefaultSniHostnames(
                    report.getClientSNIEntryList().stream()
                            .map(
                                    entry ->
                                            new ServerNamePair(
                                                    entry.getType().getValue(),
                                                    entry.getName().getBytes()))
                            .toList());
            config.setSniType(SniType.HOST_NAME);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }
        return config;
    }

    public static void filterClientCipherSuitesForFunctional(
            Config config, WebRtcPlatformReport report) {
        List<CipherSuite> functionalCipherSuites = new LinkedList<>();
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            if (report.getFunctionalServerSupportedCipherSuites().contains(suite)) {
                functionalCipherSuites.add(suite);
            }
        }
        functionalCipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCipherSuites(functionalCipherSuites);
        LOGGER.trace(
                "setting default client supported cipher suites: {}",
                functionalCipherSuites.stream().map(Enum::name).collect(Collectors.joining(", ")));
    }

    public static void filterServerCipherSuitesForFunctional(
            Config config, WebRtcPlatformReport report) {
        List<CipherSuite> functionalCipherSuites = new LinkedList<>();
        for (CipherSuite suite : config.getDefaultServerSupportedCipherSuites()) {
            if (report.getFunctionalServerSupportedCipherSuites().contains(suite)) {
                functionalCipherSuites.add(suite);
            }
        }
        functionalCipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultServerSupportedCipherSuites(functionalCipherSuites);
        LOGGER.trace(
                "setting default server supported cipher suites: {}",
                functionalCipherSuites.stream().map(Enum::name).collect(Collectors.joining(", ")));
    }

    public static WorkflowTrace createMitmEntryTrace(
            Config config,
            String connectionAliasWithServer,
            String connectionAliasWithClient,
            WebRtcPlatformReport report) {
        WorkflowTrace trace = createTrace(config);
        if (report.getResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST)
                == TestResults.TRUE) {
            trace.addTlsAction(
                    new ForwardMessagesAction(
                            connectionAliasWithClient,
                            connectionAliasWithServer,
                            new ClientHelloMessage()));
            trace.addTlsAction(
                    new ForwardMessagesAction(
                            connectionAliasWithServer,
                            connectionAliasWithClient,
                            new HelloVerifyRequestMessage()));
        }
        return trace;
    }

    /**
     * Creates a full handshake trace without applying any DTLS tricks directly. If tricks are to by
     * applied such as presenting a wrong certificate, they are to be configured through the
     * provided Config and its parameters
     *
     * <pre>
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                       Receive Till |<-----SH Done-----|
     *                           Send     |-configured CRT-->|
     *                       Dynamic Send |-------CKE------->|
     *                           Send     |----CV,CCS,FIN--->|
     * |<-------SH--------|      Send
     * |<--configured CRT-|      Send
     * |<-------SKX-------|      Send
     * |------FIN------->|   Receive Till
     * |<----NST,FIN-----|       Send
     *                       Receive Till |<------FIN--------|
     * </pre>
     *
     * @return
     */
    public static WorkflowTrace createFullMitmHandshakeTrace(
            final String clientToAttackerAlias,
            final String attackerToServerAlias,
            Config config,
            WebRtcPlatformReport report) {

        WorkflowTrace trace =
                createMitmEntryTrace(config, attackerToServerAlias, clientToAttackerAlias, report);

        // forward Victim CH to Server
        trace.addTlsAction(
                new ForwardMessagesAction(
                        clientToAttackerAlias, attackerToServerAlias, new ClientHelloMessage()));

        // receive Server SH
        trace.addTlsAction(
                new ReceiveTillAction(attackerToServerAlias, new ServerHelloDoneMessage()));

        // send Attacker FIN to server
        trace.addTlsAction(new SendAction(attackerToServerAlias, new CertificateMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(attackerToServerAlias));
        trace.addTlsAction(
                new SendAction(
                        attackerToServerAlias,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        // send Attacker SH to victim
        trace.addTlsAction(
                new SendAction(
                        clientToAttackerAlias,
                        new ServerHelloMessage(config),
                        new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(clientToAttackerAlias));
        trace.addTlsAction(
                new SendAction(
                        clientToAttackerAlias,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));

        // receive Victim FIN
        trace.addTlsAction(new ReceiveTillAction(clientToAttackerAlias, new FinishedMessage()));

        optionallyAddSessionTicketMessage(trace, report, clientToAttackerAlias);

        // send Attacker FIN to victim
        trace.addTlsAction(
                new SendAction(
                        clientToAttackerAlias,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        // receive Server FIN
        trace.addTlsAction(new ReceiveTillAction(attackerToServerAlias, new FinishedMessage()));

        return trace;
    }

    /**
     * Creates a full handshake trace between attacker and server without applying any DTLS tricks
     * directly. If tricks are to by applied such as presenting a wrong certificate, they are to be
     * configured through the provided Config and its parameters
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     *                       Receive Till |<-----SH Done-----|
     *                           Send     |---attacker CRT-->|
     *                       Dynamic Send |-------CKE------->|
     *                           Send     |----CV,CCS,FIN--->|
     *                       Receive Till |<------FIN--------|
     *
     * </pre>
     *
     * @return
     */
    public static WorkflowTrace createAttackerToServerHandshakeTrace(
            final String clientToAttackerAlias,
            final String attackerToServerAlias,
            Config config,
            WebRtcPlatformReport report) {

        WorkflowTrace trace =
                createMitmEntryTrace(config, attackerToServerAlias, clientToAttackerAlias, report);

        // forward Victim CH
        trace.addTlsAction(
                new TightForwardTillAction(
                        clientToAttackerAlias, attackerToServerAlias, new ClientHelloMessage()));

        // receive Server SH
        trace.addTlsAction(
                new ReceiveTillAction(attackerToServerAlias, new ServerHelloDoneMessage()));

        // send Attacker FIN to server
        trace.addTlsAction(new SendAction(attackerToServerAlias, new CertificateMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(attackerToServerAlias));
        trace.addTlsAction(
                new SendAction(
                        attackerToServerAlias,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        // receive Server FIN
        trace.addTlsAction(new ReceiveTillAction(attackerToServerAlias, new FinishedMessage()));

        return trace;
    }

    /**
     * Creates a full handshake trace between client and attacker without applying any DTLS tricks
     * directly. If tricks are to by applied such as presenting a wrong certificate, they are to be
     * configured through the provided Config and its parameters
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->| Receive Till
     * |<---ServerHello---|     Send
     * |<---Certificate---|     Send
     * |<--------SKE------|     Send
     * |<---CertRequest---|     Send
     * |<-ServerHelloDone-|     Send
     * |ChangeCipherSpec->| Receive Till
     *
     * </pre>
     *
     * @return
     */
    public static WorkflowTrace createClientToAttackerHandshakeTrace(
            final String clientToAttackerAlias,
            final String attackerToServerAlias,
            Config config,
            WebRtcPlatformReport report) {

        WorkflowTrace trace =
                createMitmEntryTrace(config, attackerToServerAlias, clientToAttackerAlias, report);

        // receive Victim CH
        trace.addTlsAction(new ReceiveTillAction(clientToAttackerAlias, new ClientHelloMessage()));

        // send Attacker SH etc to Victim
        trace.addTlsAction(new SendAction(clientToAttackerAlias, new ServerHelloMessage(config)));
        trace.addTlsAction(new SendDynamicServerCertificateAction(clientToAttackerAlias));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(clientToAttackerAlias));
        trace.addTlsAction(
                new SendAction(
                        clientToAttackerAlias,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));

        // receive Victim Finished
        trace.addTlsAction(new ReceiveTillAction(clientToAttackerAlias, new FinishedMessage()));

        optionallyAddSessionTicketMessage(trace, report, clientToAttackerAlias);

        // send Attacker Finished to victim
        trace.addTlsAction(
                new SendAction(
                        clientToAttackerAlias,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        return trace;
    }

    public static boolean optionallyAddSessionTicketMessage(
            WorkflowTrace trace, WebRtcPlatformReport report, String clientToAttackerAlias) {
        if (report.getResult(WebRtcProperties.CLIENT_SUPPORTS_SESSION_TICKETS)
                == TestResults.TRUE) {
            // optional session ticket (assumes config has set setAddSessionTicketTLSExtension(true)
            // as this means we have included the extension in the server hello as well, and now we
            // need to deliver)
            trace.addTlsAction(
                    new SendAction(clientToAttackerAlias, new NewSessionTicketMessage()));
            return true;
        }
        return false;
    }

    public static List<AliasedConnection> createConnectionList(Config config) {
        List<AliasedConnection> aliasedConnections = new LinkedList<>();
        aliasedConnections.add(config.getDefaultClientConnection());
        aliasedConnections.add(config.getDefaultServerConnection());
        return aliasedConnections;
    }
}
