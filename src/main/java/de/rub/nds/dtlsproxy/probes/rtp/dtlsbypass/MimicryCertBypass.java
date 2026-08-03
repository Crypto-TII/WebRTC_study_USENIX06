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
import de.rub.nds.dtlsproxy.util.CryptoUtil;
import de.rub.nds.dtlsproxy.util.TraceUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.util.MimicryEngine;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.LinkedList;
import java.util.List;

public abstract class MimicryCertBypass extends AuthBypass {

    private final boolean mimicClientCert;

    public MimicryCertBypass(
            String description,
            boolean bypassesServerAuth,
            boolean bypassesClientAuth,
            boolean mimicClientCert) {
        super(description, bypassesServerAuth, bypassesClientAuth);
        this.mimicClientCert = mimicClientCert;
    }

    public boolean isMimicClientCert() {
        return mimicClientCert;
    }

    @Override
    public Config createConfig(ProxyConfiguration configuration, WebRtcPlatformReport report) {

        Config config =
                TraceUtil.applyRtpConfig(
                        TraceUtil.getFunctionalConfig(
                                configuration,
                                report,
                                CLIENT_TO_ATTACKER_CONNECTION,
                                ATTACKER_TO_SERVER_CONNECTION));

        if (mimicClientCert && report.getExampleClientCertificateChain() == null) {
            throw new RuntimeException(
                    "Failed to create bypass config: No example client certificate chain found");
        }

        if (!mimicClientCert && report.getExampleServerCertificateChain() == null) {
            throw new RuntimeException(
                    "Failed to create bypass config: No example server certificate chain found");
        }

        List<X509CertificateConfig> certificateConfigs = new LinkedList<>();
        X509CertificateChain exampleCertificateChain =
                mimicClientCert
                        ? report.getExampleClientCertificateChain()
                        : report.getExampleServerCertificateChain();
        for (int i = 0; i < exampleCertificateChain.size(); i++) {
            certificateConfigs.add(new X509CertificateConfig());
        }
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleCertificateChain);

        // sets the mimicked cert as default for all connections, incl. clientToAttacker
        config.setDefaultExplicitCertificateChain(mimicryCertificateChain);
        config.setCertificateChainConfig(certificateConfigs);
        if (mimicClientCert) {
            CryptoUtil.adjustClientCiphers(
                    config, exampleCertificateChain.getLeaf().getCertificateKeyType());
        } else {
            CryptoUtil.adjustServerCiphers(
                    config, exampleCertificateChain.getLeaf().getCertificateKeyType());
        }

        return config;
    }
}
