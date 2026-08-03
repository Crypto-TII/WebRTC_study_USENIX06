/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.post;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.probes.dtls.DtlsProbe;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.JaFingerprintCalculator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import org.apache.commons.lang3.tuple.Pair;

public class PostAnalyzer {

    private WebRtcPlatformReport report;

    public PostAnalyzer(WebRtcPlatformReport report) {
        this.report = report;
    }

    public void finalizeReport() {
        if (!report.getRemoteClientHelloWitnessList().isEmpty()
                && !report.getLocalClientHelloWitnessList().isEmpty()) {
            // Sometimes we are the client, sometimes we are the server, this is not good. We want
            // conistency
            report.putResult(WebRtcProperties.CLIENT_HELLO_DIRECTION_CONSISTENT, TestResults.FALSE);
        } else {
            // We are always either the client or the server, no mixing
            report.putResult(WebRtcProperties.CLIENT_HELLO_DIRECTION_CONSISTENT, TestResults.TRUE);
        }
        report.putResult(
                WebRtcProperties.INBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER,
                report.getJa3LocalClientStringSet().size());
        report.putResult(
                WebRtcProperties.INBOUND_SERVER_HELLO_FINGERPRINT_COUNTER,
                report.getJa3sRemoteServerStringSet().size());
        report.putResult(
                WebRtcProperties.OUTBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER,
                report.getJa3RemoteClientStringSet().size());
        report.putResult(
                WebRtcProperties.OUTBOUND_SERVER_HELLO_FINGERPRINT_COUNTER,
                report.getJa3sLocalServerStringSet().size());
        report.putResult(
                WebRtcProperties.INBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER,
                report.getLocalServerCertificateWitnessList().size());
        report.putResult(
                WebRtcProperties.OUTBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER,
                report.getRemoteServerCertificateWitnessList().size());
        report.putResult(
                WebRtcProperties.INBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER,
                report.getLocalClientCertificateWitnessList().size());
        report.putResult(
                WebRtcProperties.OUTBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER,
                report.getRemoteClientCertificateWitnessList().size());
    }

    public void consume(State state, ConnectionInterface connection) {
        FilterDirection filterDirection = connection.getCreatedFromFilterDirection();

        ClientHelloMessage originalClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.CLIENT_HELLO,
                                DtlsProbe.CLIENT_TO_ATTACKER_CONNECTION);
        ClientHelloMessage forwardedClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.CLIENT_HELLO,
                                DtlsProbe.ATTACKER_TO_SERVER_CONNECTION);
        HelloVerifyRequestMessage helloVerifyRequestMessage =
                (HelloVerifyRequestMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.HELLO_VERIFY_REQUEST,
                                DtlsProbe.ATTACKER_TO_SERVER_CONNECTION);
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.SERVER_HELLO,
                                DtlsProbe.ATTACKER_TO_SERVER_CONNECTION);
        CertificateMessage serverCertificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.CERTIFICATE,
                                DtlsProbe.ATTACKER_TO_SERVER_CONNECTION);
        CertificateMessage clientCertificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(),
                                HandshakeMessageType.CERTIFICATE,
                                DtlsProbe.CLIENT_TO_ATTACKER_CONNECTION);

        consumeClientHello(connection, filterDirection, originalClientHello);
        consumeHvr(connection, filterDirection, helloVerifyRequestMessage);
        // If we forwarded it as is, we can also check the response to the client hello

        // If an original CH is present, check if we forwarded a matching CH
        if (isServerHelloUsable(originalClientHello, forwardedClientHello)) {
            // The forwarded message is the same as the original message
            // We can now check the response to the client hello
            // Check if we received a server hello
            consumeServerHello(connection, filterDirection, serverHello);

            consumeServerCertificate(connection, filterDirection, serverCertificateMessage);
        }
        consumeClientCertificate(connection, filterDirection, clientCertificateMessage);
    }

    private boolean isServerHelloUsable(
            ClientHelloMessage originalClientHello, ClientHelloMessage forwardedClientHello) {

        // The server hello is usable in 2 cases

        // we did not forward a client hello message, but received a server hello through other
        // means
        if (forwardedClientHello == null) {
            return true;
        }

        // we received a client hello and forwarded an identical copy
        if (originalClientHello != null) {
            if (JaFingerprintCalculator.getJa3FingerprintString(originalClientHello)
                    .equals(
                            JaFingerprintCalculator.getJa3FingerprintString(
                                    forwardedClientHello))) {
                return true;
            }
        }

        return false;
    }

    private void consumeClientCertificate(
            ConnectionInterface connection,
            FilterDirection filterDirection,
            CertificateMessage clientCertificateMessage) {
        if (clientCertificateMessage != null) {
            if (filterDirection == FilterDirection.INBOUND) {
                // The local side is the client
                report.getLocalClientCertificateWitnessList()
                        .add(Pair.of(clientCertificateMessage, connection));
            } else {
                // The remote side is the client
                report.getRemoteServerCertificateWitnessList()
                        .add(Pair.of(clientCertificateMessage, connection));
            }
        }
    }

    private void consumeServerCertificate(
            ConnectionInterface connection,
            FilterDirection filterDirection,
            CertificateMessage serverCertificateMessage) {
        // Get the certificate message
        if (serverCertificateMessage != null) {
            if (filterDirection == FilterDirection.OUTBOUND) {
                // The local side is the server
                report.getLocalServerCertificateWitnessList()
                        .add(Pair.of(serverCertificateMessage, connection));
            } else {
                // The remote side is the server
                report.getRemoteServerCertificateWitnessList()
                        .add(Pair.of(serverCertificateMessage, connection));
            }
        }
    }

    private void consumeServerHello(
            ConnectionInterface connection,
            FilterDirection filterDirection,
            ServerHelloMessage serverHello) {
        if (serverHello != null) {
            // We received a server hello
            if (filterDirection == FilterDirection.OUTBOUND) {
                report.getLocalServerHelloWitnessList().add(Pair.of(serverHello, connection));
                report.getJa3sLocalServerStringSet()
                        .add(JaFingerprintCalculator.getJa3sFingerprintString(serverHello));
            } else {
                report.getRemoteServerHelloWitnessList().add(Pair.of(serverHello, connection));
                report.getJa3sRemoteServerStringSet()
                        .add(JaFingerprintCalculator.getJa3sFingerprintString(serverHello));
            }
        }
    }

    private void consumeHvr(
            ConnectionInterface connection,
            FilterDirection filterDirection,
            HelloVerifyRequestMessage helloVerifyRequestMessage) {
        if (helloVerifyRequestMessage != null) {
            if (filterDirection == FilterDirection.OUTBOUND) {
                report.getLocalCookieWitnessList()
                        .add(Pair.of(helloVerifyRequestMessage.getCookie().getValue(), connection));
            } else {
                report.getRemoteCookieWitnessList()
                        .add(Pair.of(helloVerifyRequestMessage.getCookie().getValue(), connection));
            }
        }
    }

    private void consumeClientHello(
            ConnectionInterface connection,
            FilterDirection filterDirection,
            ClientHelloMessage originalClientHello) {
        if (originalClientHello != null) {
            // We actually received a client hello
            if (filterDirection == FilterDirection.INBOUND) {
                // The local side is the client
                report.getLocalClientHelloWitnessList()
                        .add(Pair.of(originalClientHello, connection));
                report.getJa3LocalClientStringSet()
                        .add(JaFingerprintCalculator.getJa3FingerprintString(originalClientHello));
            } else {
                // The remote side is the client
                report.getRemoteClientHelloWitnessList()
                        .add(Pair.of(originalClientHello, connection));
                report.getJa3RemoteClientStringSet()
                        .add(JaFingerprintCalculator.getJa3FingerprintString(originalClientHello));
            }
        }
    }
}
