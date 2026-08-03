/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.util;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.interfaces.DHPrivateKey;

public final class CryptoUtil {

    public static void adjustPrivateKey(X509CertificateConfig config, PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
            config.setRsaPrivateKey(rsaKey.getPrivateExponent());
            config.setRsaModulus(rsaKey.getModulus());
            config.setPublicKeyType(X509PublicKeyType.RSA);
        } else if (privateKey instanceof DSAPrivateKey) {
            DSAPrivateKey dsaKey = (DSAPrivateKey) privateKey;
            config.setDsaGenerator(dsaKey.getParams().getG());
            config.setDsaPrimeP(dsaKey.getParams().getP());
            config.setDsaPrimeQ(dsaKey.getParams().getQ());
            config.setDsaPrivateKey(dsaKey.getX());
            config.setPublicKeyType(X509PublicKeyType.DSA);
        } else if (privateKey instanceof DHPrivateKey) {
            DHPrivateKey dhKey = (DHPrivateKey) privateKey;
            config.setDhPrivateKey(dhKey.getX());
            config.setDhModulus(dhKey.getParams().getP());
            config.setDhGenerator(dhKey.getParams().getG());
            config.setPublicKeyType(X509PublicKeyType.DH);
        } else if (privateKey instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) privateKey;
            config.setEcPrivateKey(ecKey.getS());
            config.setDefaultSubjectNamedCurve(X509NamedCurve.getX509NamedCurve(ecKey));
            config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
        } else {
            throw new UnsupportedOperationException(
                    "This private key is not supporter:" + privateKey.toString());
        }
    }

    private static List<CipherSuite> filterValidCiphers(
            X509PublicKeyType keyType, List<CipherSuite> toFilterFrom) {

        List<CipherSuite> validSuites = new LinkedList<>();

        // Currently not account for the version
        for (CipherSuite suite : toFilterFrom) {
            if (!suite.isRealCipherSuite() || suite.isTls13()) {
                // TODO DTLS 1.3 not supported yet
                continue;
            }
            if (suite.getCipherType() == CipherType.STREAM) {
                // STREAM ciphers are not allowed in DTLS
                continue;
            }
            if (keyType.isEc()) {
                if (suite.getKeyExchangeAlgorithm().isKeyExchangeStaticEcdh() || suite.isECDSA()) {
                    validSuites.add(suite);
                }
            } else if (keyType == X509PublicKeyType.RSA
                    || keyType == X509PublicKeyType.RSAES_OAEP
                    || keyType == X509PublicKeyType.RSASSA_PSS) {
                if (suite.getKeyExchangeAlgorithm().isKeyExchangeRsa()
                        || suite.getKeyExchangeAlgorithm().mustUseRsaSignatures()) {
                    validSuites.add(suite);
                }
            } else if (keyType == X509PublicKeyType.DSA) {
                if (suite.isDSS()) { // TODO this is not correct but nobody uses it anyways
                    validSuites.add(suite);
                }
            }
        }
        return validSuites;
    }

    private static List<CipherSuite> filterValidCiphers(PrivateKey privateKey) {

        List<CipherSuite> implementedSuites = CipherSuite.getImplemented();
        List<CipherSuite> validSuites = new LinkedList<>();

        // Currently not account for the version
        for (CipherSuite suite : implementedSuites) {
            if (!suite.isRealCipherSuite() || suite.isTls13()) {
                // TODO DTLS 1.3 not supported yet
                continue;
            }
            if (suite.getCipherType() == CipherType.STREAM) {
                // STREAM ciphers are not allowed in DTLS
                continue;
            }
            if (privateKey instanceof ECPrivateKey) {
                if (suite.getKeyExchangeAlgorithm().isKeyExchangeStaticEcdh() || suite.isECDSA()) {
                    validSuites.add(suite);
                }
            } else if (privateKey instanceof RSAPrivateKey) {
                if (suite.getKeyExchangeAlgorithm().isKeyExchangeRsa()
                        || suite.getKeyExchangeAlgorithm().mustUseRsaSignatures()) {
                    validSuites.add(suite);
                }
            } else if (privateKey instanceof DSAPrivateKey) {
                if (suite.isDSS()) { // TODO this is not correct but nobody uses it anyways
                    validSuites.add(suite);
                }
            }
        }
        return validSuites;
    }

    private static List<SignatureAndHashAlgorithm> filterValidSignatureAndHashAlgorithms(
            X509PublicKeyType keyType) {
        List<SignatureAndHashAlgorithm> implemented = SignatureAndHashAlgorithm.getImplemented();
        List<SignatureAndHashAlgorithm> validSignAndHashAlgorithms = new LinkedList<>();
        for (SignatureAndHashAlgorithm algo : implemented) {
            if (keyType.isEc()) {
                if (algo.name().contains("ECDSA")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            } else if (keyType == X509PublicKeyType.RSA
                    || keyType == X509PublicKeyType.RSAES_OAEP
                    || keyType == X509PublicKeyType.RSASSA_PSS) {
                if (algo.name().contains("RSA")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            } else if (keyType == X509PublicKeyType.DSA) {
                if (algo.name().contains("DSS")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            }
        }
        return validSignAndHashAlgorithms;
    }

    private static List<SignatureAndHashAlgorithm> filterValidSignatureAndHashAlgorithms(
            PrivateKey privateKey) {
        List<SignatureAndHashAlgorithm> implemented = SignatureAndHashAlgorithm.getImplemented();
        List<SignatureAndHashAlgorithm> validSignAndHashAlgorithms = new LinkedList<>();
        for (SignatureAndHashAlgorithm algo : implemented) {
            if (privateKey instanceof ECPrivateKey) {
                if (algo.name().contains("ECDSA")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            } else if (privateKey instanceof RSAPrivateKey) {
                if (algo.name().contains("RSA")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            } else if (privateKey instanceof DSAPrivateKey) {
                if (algo.name().contains("DSS")) {
                    validSignAndHashAlgorithms.add(algo);
                }
            }
        }
        return validSignAndHashAlgorithms;
    }

    public static void adjustServerCiphers(Config config, X509PublicKeyType keyType) {
        List<CipherSuite> validSuites =
                filterValidCiphers(keyType, config.getDefaultServerSupportedCipherSuites());
        if (validSuites.isEmpty()) {
            throw new RuntimeException(
                    "No applicable cipher suites found in given default cipher suites");
        }
        List<SignatureAndHashAlgorithm> validSignatureAndHashAlgorithms =
                filterValidSignatureAndHashAlgorithms(keyType);
        config.setDefaultServerSupportedCipherSuites(validSuites);
        config.setDefaultServerSupportedCertificateSignAlgorithms(validSignatureAndHashAlgorithms);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(validSignatureAndHashAlgorithms);
    }

    public static void adjustClientCiphers(Config config, X509PublicKeyType keyType) {
        List<CipherSuite> validSuites =
                filterValidCiphers(keyType, config.getDefaultClientSupportedCipherSuites());
        if (validSuites.isEmpty()) {
            throw new RuntimeException(
                    "No applicable cipher suites found in given default cipher suites:\nneed "
                            + keyType.name()
                            + "\nsupport "
                            + config.getDefaultClientSupportedCipherSuites().stream()
                                    .map(Enum::name)
                                    .collect(Collectors.joining(", ")));
        }
        List<SignatureAndHashAlgorithm> validSignatureAndHashAlgorithms =
                filterValidSignatureAndHashAlgorithms(keyType);
        config.setDefaultClientSupportedCipherSuites(validSuites);
        config.setDefaultClientSupportedCertificateSignAlgorithms(validSignatureAndHashAlgorithms);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(validSignatureAndHashAlgorithms);
    }

    public static void adjustClientCiphers(Config config, PrivateKey privateKey) {
        List<CipherSuite> validSuites = filterValidCiphers(privateKey);
        if (validSuites.isEmpty()) {
            throw new RuntimeException(
                    "No applicable cipher suites found in given default cipher suites");
        }
        List<SignatureAndHashAlgorithm> validSignatureAndHashAlgorithms =
                filterValidSignatureAndHashAlgorithms(privateKey);
        config.setDefaultClientSupportedCipherSuites(validSuites);
        config.setDefaultClientSupportedCertificateSignAlgorithms(validSignatureAndHashAlgorithms);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(validSignatureAndHashAlgorithms);
    }

    public static void adjustServerCiphers(Config config, PrivateKey privateKey) {
        List<CipherSuite> validSuites = filterValidCiphers(privateKey);
        if (validSuites.isEmpty()) {
            throw new RuntimeException(
                    "No applicable cipher suites found in given default cipher suites");
        }
        List<SignatureAndHashAlgorithm> validSignatureAndHashAlgorithms =
                filterValidSignatureAndHashAlgorithms(privateKey);
        config.setDefaultServerSupportedCipherSuites(validSuites);
        config.setDefaultServerSupportedCertificateSignAlgorithms(validSignatureAndHashAlgorithms);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(validSignatureAndHashAlgorithms);
    }
}
