/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.demultiplexer;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.util.JaFingerprintCalculator;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class analyzes hints for different configured DTLS endpoints. It compares concurrent
 * connections, as well as connections from multiple individual runs. Differently endpoints are
 * identified by either static port number or different IP address (does not mean they are
 * necessarily different) or by a different configuration. We consider a media-server different if:
 * - it sends structurally different ClientHello packages (same besides ephemeral values) - it sends
 * structurally different ServerHello packages (same besides ephemeral values) - it sends
 * *sometimes* different certificates (either as client or as server)
 */
public class Demultiplexer {

    public Demultiplexer() {}

    public boolean isStructurallyDifferentClientHello(
            ClientHelloMessage firstClientHello, ClientHelloMessage secondClientHello) {
        return !Arrays.equals(
                JaFingerprintCalculator.getJa3FingerprintHash(secondClientHello),
                JaFingerprintCalculator.getJa3FingerprintHash(firstClientHello));
    }

    public int getStructurallyDifferentClientHelloCount(
            List<ClientHelloMessage> seenFittingClientHelloMessages) {
        List<ClientHelloMessage> differentMessages = new ArrayList<>();
        for (ClientHelloMessage candidateMessage : seenFittingClientHelloMessages) {
            for (ClientHelloMessage seenMessage : differentMessages) {
                if (isStructurallyDifferentClientHello(candidateMessage, seenMessage)) {
                    differentMessages.add(candidateMessage);
                    break;
                }
            }
        }
        return differentMessages.size();
    }

    public int getStructurallyDifferentServerHelloCount(
            List<ServerHelloMessage> seenFittingServerHelloMessages) {
        List<ServerHelloMessage> differentMessages = new ArrayList<>();
        for (ServerHelloMessage candidateMessage : seenFittingServerHelloMessages) {
            for (ServerHelloMessage seenMessage : differentMessages) {
                if (isStructurallyDifferentServerHello(candidateMessage, seenMessage)) {
                    differentMessages.add(candidateMessage);
                    break;
                }
            }
        }
        return differentMessages.size();
    }

    public boolean isStructurallyDifferentServerHello(
            ServerHelloMessage firstServerHello, ServerHelloMessage secondServerHello) {
        return !Arrays.equals(
                JaFingerprintCalculator.getJa3sFingerprintHash(secondServerHello),
                JaFingerprintCalculator.getJa3sFingerprintHash(firstServerHello));
    }

    /**
     * Returns the number of different certificates seen in the list of certificates
     *
     * @param seenCertificates
     * @return
     */
    public int getSemiStaticCertificateCount(List<CertificateMessage> seenCertificates) {
        Set<X509CertificateChain> certificateChainSet = new HashSet<>();
        for (CertificateMessage certificate : seenCertificates) {
            X509CertificateChain chain =
                    new X509CertificateChain(certificate.getX509CertificateListFromEntries());
            certificateChainSet.add(chain);
        }
        return certificateChainSet.size();
    }

    public boolean hasSemiStaticCertificate(List<CertificateMessage> seenCertificates) {
        int certificateCount = getSemiStaticCertificateCount(seenCertificates);
        return certificateCount > 1 && certificateCount != seenCertificates.size();
    }
}
