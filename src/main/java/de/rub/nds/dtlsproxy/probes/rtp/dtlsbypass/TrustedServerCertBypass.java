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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public class TrustedServerCertBypass extends TrustedCertBypass {

    public TrustedServerCertBypass() {
        super(
                "Present trusted server certificate to client, ignore server",
                true,
                false,
                false,
                true);
    }

    /**
     * Creates a trace based on the assumption that the client accepts certificates not matching the
     * SDP fingerprint, but being verifiable through the client trust store.
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
     * |-FinishedMessage->| Receive Till
     *
     * </pre>
     */
    public WorkflowTrace createTrace(
            WebRtcPlatformReport report, ProxyConfiguration proxyConfiguration) {
        return TraceUtil.createClientToAttackerHandshakeTrace(
                CLIENT_TO_ATTACKER_CONNECTION,
                ATTACKER_TO_SERVER_CONNECTION,
                createConfig(proxyConfiguration, report),
                report);
    }

    @Override
    public boolean isApplicable(WebRtcPlatformReport report) {

        if (!basicExecutionRequirementsMet(report)) {
            return false;
        }

        if (!isFalse(report, WebRtcProperties.CLIENT_REJECTS_PROVIDED_CERTIFICATE)) {
            return false;
        }

        return true;
    }
}
