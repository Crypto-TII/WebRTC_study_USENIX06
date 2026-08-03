/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import de.rub.nds.dtlsproxy.config.ProxyConfiguration;
import de.rub.nds.dtlsproxy.report.WebRtcPlatformReport;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.signatureengine.keyparsers.PemUtil;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.*;
import java.security.PrivateKey;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class X509Util {

    private static final Logger LOGGER = LogManager.getLogger();

    private static HashMap<SignatureAndHashAlgorithm, Pair<List<CertificateBytes>, PrivateKey>>
            certificateCache = null;

    private X509Util() {}

    /**
     * Loads potential external certificates and private keys from the paths specified in the
     * command line flags. Each certificate with a distinct signature and hash algorithm will be put
     * in a separate entry in the cache
     */
    public static void initCache(ProxyConfiguration proxyConfiguration) {

        String[] externalCertPaths = proxyConfiguration.getExternalCertificates();
        String[] externalKeyPaths = proxyConfiguration.getExternalKeys();

        if (externalCertPaths == null || externalKeyPaths == null) {
            certificateCache = new HashMap<>();
            return;
        }

        if (externalCertPaths.length != externalKeyPaths.length) {
            throw new RuntimeException(
                    "Failed to load certificates: amount of certificates and private keys don't match");
        }

        if (externalCertPaths.length == 0) {
            return;
        }

        HashMap<SignatureAndHashAlgorithm, Pair<List<CertificateBytes>, PrivateKey>> tmpCache =
                new HashMap<>();
        for (int i = 0; i < externalCertPaths.length; i++) {
            final String certPath = externalCertPaths[i];
            final String keyPath = externalKeyPaths[i];

            List<CertificateBytes> certificateBytes;
            X509CertificateChain certificateChain;
            PrivateKey privateKey;
            try {
                certificateBytes =
                        CertificateIo.readPemCertificateByteList(new FileInputStream(certPath));
                certificateChain = CertificateIo.readPemChain(new FileInputStream(certPath));
                privateKey = PemUtil.readPrivateKey(new File(keyPath));
            } catch (IOException e) {
                LOGGER.warn("Could not load external certificate or key! ", e);
                throw new RuntimeException(e);
            }

            X509Certificate certLeaf = certificateChain.getLeaf();
            SignatureAndHashAlgorithm algorithm =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                            certLeaf.getSignatureAlgorithm(), certLeaf.getHashAlgorithm());

            tmpCache.put(algorithm, new Pair<>(certificateBytes, privateKey));
            LOGGER.debug("External {} certificate loaded", algorithm);
        }

        certificateCache = new HashMap<>();
        certificateCache.putAll(tmpCache);
    }

    public static void applyTrustedCertificate(
            WebRtcPlatformReport report,
            Config config,
            ProxyConfiguration proxyConfiguration,
            boolean isClientCertificate) {

        if (certificateCache == null) {
            initCache(proxyConfiguration);
        }

        // decide whether to load an EC or an RSA cert
        SignatureAndHashAlgorithm defaultAlgorithm =
                isClientCertificate
                        ? report.getDefaultClientSelectedSignatureAndHashAlgorithm()
                        : report.getDefaultServerSelectedSignatureAndHashAlgorithm();

        for (SignatureAndHashAlgorithm algorithm : getCachedCertificateAlgorithms()) {
            if (algorithm == defaultAlgorithm) {
                LOGGER.trace(
                        "Selecting {}, as set as a selected default algorithm",
                        defaultAlgorithm.name());
                applyTrustedCertificate(defaultAlgorithm, config);
                return;
            }
        }

        // no direct match with default selected algorithm
        // search offered algorithms for a fitting one and set as default
        List<SignatureAndHashAlgorithm> supportedAlgorithms =
                isClientCertificate
                        ? report.getServerRequestedSignatureAndHashAlgorithms()
                        : report.getClientSupportedSignatureAndHashAlgorithms();

        if (supportedAlgorithms == null || supportedAlgorithms.isEmpty()) {
            // report results insufficient
            throw new RuntimeException(
                    "Can not determine certificate key type: No supported signature algorithms set");
        }

        // iterate for a match
        for (SignatureAndHashAlgorithm desiredAlgorithm : supportedAlgorithms) {
            for (SignatureAndHashAlgorithm cachedAlgorithm : getCachedCertificateAlgorithms()) {
                if (desiredAlgorithm == cachedAlgorithm) {
                    LOGGER.trace("Selecting {}, as offered by peer", desiredAlgorithm.name());
                    applyTrustedCertificate(desiredAlgorithm, config);
                    return;
                }
            }
        }

        // no match in supported and cached algorithms
        LOGGER.warn(
                "Failed to set certificate: no cert for supported algorithms cached."
                        + "Cached algorithms: {}, peer supported algorithms: {}",
                getCachedCertificateAlgorithms().stream()
                        .map(
                                a ->
                                        a.getSignatureAlgorithm().getHumanReadable()
                                                + " with "
                                                + a.getHashAlgorithm().getJavaName())
                        .collect(Collectors.joining(", ")),
                supportedAlgorithms.stream()
                        .map(
                                a ->
                                        a.getSignatureAlgorithm().getHumanReadable()
                                                + " with "
                                                + a.getHashAlgorithm().getJavaName())
                        .collect(Collectors.joining(", ")));
        throw new RuntimeException(
                "Failed to set certificate: no cert for supported algorithms cached.");
    }

    private static Set<SignatureAndHashAlgorithm> getCachedCertificateAlgorithms() {

        if (certificateCache == null) {
            return new HashSet<>();
        }

        return certificateCache.keySet();
    }

    private static void applyTrustedCertificate(
            SignatureAndHashAlgorithm algorithm, Config config) {

        if (!certificateCache.containsKey(algorithm)) {
            throw new RuntimeException(
                    "No certificate with this signature algorithm cached: " + algorithm);
        }

        Pair<List<CertificateBytes>, PrivateKey> keyPair = certificateCache.get(algorithm);
        List<CertificateBytes> certificate = keyPair.getLeftElement();
        PrivateKey privateKey = keyPair.getRightElement();

        config.setDefaultExplicitCertificateChain(certificate);
        CryptoUtil.adjustPrivateKey(config.getDefaultX509CertificateConfig(), privateKey);
        // always adjust server ciphers because setting this through
        // setDefaultExplicitCertificateChain will make all contexts presents this cert so we need
        // to adjust server ciphers in case we need them
        CryptoUtil.adjustServerCiphers(config, privateKey);

        LOGGER.trace("Certificate of algorithm {} applied", algorithm.name());
    }

    /**
     * Will try to apply the default server selected Signature and Hash Algorithm to the certificate
     * configuration. If no default is set, the first algorithm in the supported list is selected
     */
    public static void applySupportedSignatureAndHashAlgorithm(
            Config config, WebRtcPlatformReport report, boolean isClientCertificate) {

        SignatureAndHashAlgorithm algorithm = null;

        SignatureAndHashAlgorithm defaultAlgorithm =
                isClientCertificate
                        ? report.getDefaultClientSelectedSignatureAndHashAlgorithm()
                        : report.getDefaultServerSelectedSignatureAndHashAlgorithm();

        if (defaultAlgorithm != null && isImplemented(defaultAlgorithm)) {
            algorithm = defaultAlgorithm;
            LOGGER.trace(
                    "Setting {} as signature algorithm because it is the selected default",
                    algorithm);
        } else {
            if (isClientCertificate) {
                if (report.getServerRequestedSignatureAndHashAlgorithms() != null
                        && !report.getServerRequestedSignatureAndHashAlgorithms().isEmpty()) {

                    // iterate server supported algorithms until we find one that we implement
                    for (SignatureAndHashAlgorithm supported :
                            report.getServerRequestedSignatureAndHashAlgorithms()) {
                        if (isImplemented(supported)) {
                            algorithm = supported;
                            LOGGER.trace(
                                    "Setting {} as signature algorithm because it is the first "
                                            + "implemented algorithm in the server's requested list",
                                    algorithm);
                            break;
                        }
                    }
                }
            } else {
                if (report.getClientSupportedSignatureAndHashAlgorithms() != null
                        && !report.getClientSupportedSignatureAndHashAlgorithms().isEmpty()) {

                    // iterate client supported algorithms until we find one that we implement
                    for (SignatureAndHashAlgorithm supported :
                            report.getClientSupportedSignatureAndHashAlgorithms()) {
                        if (isImplemented(supported)) {
                            algorithm = supported;
                            LOGGER.trace(
                                    "Setting {} as signature algorithm because it is the first "
                                            + "implemented algorithm in the client's supported list",
                                    algorithm);
                            break;
                        }
                    }
                }
            }
        }

        if (algorithm == null) {
            throw new RuntimeException(
                    "Failed to determine signature algorithm. No default and no supported algorithms in report");
        }

        config.setCertificateChainConfig(List.of(getDefaultAttackerCertConfig(algorithm)));
    }

    private static X509CertificateConfig getDefaultAttackerCertConfig(
            SignatureAndHashAlgorithm algorithm) {
        X509CertificateConfig certificateConfig = new X509CertificateConfig();
        List<Pair<X500AttributeType, String>> subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "DTLS Analysis Proxy"));
        certificateConfig.setSubject(subject);
        certificateConfig.setIssuer(subject);
        certificateConfig.setPublicKeyType(getX509PublicKeyType(algorithm));
        certificateConfig.setSignatureAlgorithm(getX509SignatureAlgorithm(algorithm));
        return certificateConfig;
    }

    private static X509SignatureAlgorithm getX509SignatureAlgorithm(
            SignatureAndHashAlgorithm algorithm) {
        switch (algorithm) {
            case RSA_SHA1:
                return X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION;
            case RSA_SHA224:
                return X509SignatureAlgorithm.SHA224_WITH_RSA_ENCRYPTION;
            case RSA_SHA256:
                return X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION;
            case RSA_SHA384:
                return X509SignatureAlgorithm.SHA384_WITH_RSA_ENCRYPTION;
            case RSA_SHA512:
                return X509SignatureAlgorithm.SHA512_WITH_RSA_ENCRYPTION;
            case ECDSA_SHA1:
                return X509SignatureAlgorithm.ECDSA_WITH_SHA1;
            case ECDSA_SHA224:
                return X509SignatureAlgorithm.ECDSA_WITH_SHA224;
            case ECDSA_SHA256:
                return X509SignatureAlgorithm.ECDSA_WITH_SHA256;
            case ECDSA_SHA384:
                return X509SignatureAlgorithm.ECDSA_WITH_SHA384;
            case ECDSA_SHA512:
                return X509SignatureAlgorithm.ECDSA_WITH_SHA512;
            default:
                throw new RuntimeException("Algorithm not implemented: " + algorithm);
        }
    }

    private static X509PublicKeyType getX509PublicKeyType(SignatureAndHashAlgorithm algorithm) {
        switch (algorithm) {
            case RSA_SHA1: // fall
            case RSA_SHA224: // fall
            case RSA_SHA256: // fall
            case RSA_SHA384: // fall
            case RSA_SHA512: // fall
                return X509PublicKeyType.RSA;
            case ECDSA_SHA1: // fall
            case ECDSA_SHA224: // fall
            case ECDSA_SHA256: // fall
            case ECDSA_SHA384: // fall
            case ECDSA_SHA512: // fall
                return X509PublicKeyType.ECDH_ECDSA;
            default:
                throw new RuntimeException("Algorithm not implemented: " + algorithm);
        }
    }

    private static boolean isImplemented(SignatureAndHashAlgorithm algorithm) {
        switch (algorithm) {
            case RSA_SHA1: // fall
            case RSA_SHA224: // fall
            case RSA_SHA256: // fall
            case RSA_SHA384: // fall
            case RSA_SHA512: // fall
            case ECDSA_SHA1: // fall
            case ECDSA_SHA224: // fall
            case ECDSA_SHA256: // fall
            case ECDSA_SHA384: // fall
            case ECDSA_SHA512: // fall
                return true;
            default:
                return false;
        }
    }
}
