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
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.dtlsproxy.util.X509Util;
import de.rub.nds.tlsattacker.core.config.Config;

public abstract class TrustedCertBypass extends AuthBypass {

    private final boolean presentTrustedClientCert;
    private final boolean presentTrustedServerCert;

    public TrustedCertBypass(
            String description,
            boolean bypassesServerAuth,
            boolean bypassesClientAuth,
            boolean presentTrustedClientCert,
            boolean presentTrustedServerCert) {
        super(description, bypassesServerAuth, bypassesClientAuth);
        this.presentTrustedClientCert = presentTrustedClientCert;
        this.presentTrustedServerCert = presentTrustedServerCert;
    }

    @Override
    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {

        if (configuration.getExternalCertificates() == null
                || configuration.getExternalKeys() == null) {
            throw new RuntimeException(
                    "Failed to create config for bypass: "
                            + "Trusted certificate and private key were not specified as command line parameters");
        }

        Config config =
                TraceUtil.applyRtpConfig(
                        TraceUtil.getFunctionalConfig(
                                configuration,
                                report,
                                CLIENT_TO_ATTACKER_CONNECTION,
                                ATTACKER_TO_SERVER_CONNECTION));

        if (presentTrustedClientCert) {
            X509Util.applyTrustedCertificate(report, config, configuration, true);
        }
        if (presentTrustedServerCert) {
            X509Util.applyTrustedCertificate(report, config, configuration, false);
        }

        return config;
    }
}
