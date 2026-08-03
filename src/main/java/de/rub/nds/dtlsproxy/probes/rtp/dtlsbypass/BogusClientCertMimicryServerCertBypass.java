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

public class BogusClientCertMimicryServerCertBypass extends MimicryCertBypass {

    public BogusClientCertMimicryServerCertBypass() {
        super(
                "present mimicked server certificate, present unexpected arbitrary client certificate",
                true,
                true,
                false);
    }

    /**
     * Creates a trace based on the assumption that the server accepts certificates not matching the
     * SDP fingerprint, but looking alike the original. Also assumes that the client accepts any
     * certificate.
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
     * |<-------SH--------|      Send
     * |<---mimicry CRT---|      Send
     * |<-------SKX-------|      Send
     * |------FIN------->|   Receive Till
     * |<----NST,FIN-----|       Send
     *                       Receive Till |<------FIN--------|
     *
     * </pre>
     */
    public WorkflowTrace createTrace(
            WebRtcPlatformReport report, ProxyConfiguration proxyConfiguration) {
        return TraceUtil.createFullMitmHandshakeTrace(
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
        if (!isTrue(report, WebRtcProperties.SERVER_REQUESTS_CERTIFICATE)) {
            return false;
        }

        if (!isFalse(report, WebRtcProperties.CLIENT_REJECTS_MIMICRY_CERTIFICATE)) {
            return false;
        }

        if (!isFalse(report, WebRtcProperties.SERVER_VERIFIES_CERTIFICATE)) {
            return false;
        }

        if (report.getExampleServerCertificateChain() == null) {
            return false;
        }

        return true;
    }
}
