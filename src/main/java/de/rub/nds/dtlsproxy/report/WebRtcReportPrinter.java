/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.report;

import de.rub.nds.dtlsproxy.enums.MediaProtocol;
import de.rub.nds.dtlsproxy.enums.MitmProperties;
import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.enums.WebRtcProperties;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportPrinter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.util.JaFingerprintCalculator;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.Objects;
import java.util.function.Function;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.Days;

public class WebRtcReportPrinter extends ReportPrinter<WebRtcPlatformReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    public WebRtcReportPrinter(
            ScannerDetail detail,
            PrintingScheme scheme,
            boolean printColorful,
            WebRtcPlatformReport scanReport) {
        super(detail, scheme, printColorful, scanReport);
    }

    @Override
    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        prettyAppendHeading(
                builder, report.getTargetName() + " - " + report.getLockedFilterDirection());
        appendTestProperties(builder);

        if (report.getResult(WebRtcProperties.COMPLETELY_FUNCTIONAL) == TestResults.FALSE) {
            return builder.toString();
        } else {
            appendGenericProperties(builder);
            appendDefaultSelected(builder);
            appendSrtpProtectionProfiles(builder);
            appendSrtpMKI(builder);
            appendCipherSuites(builder);
            appendProtocolVersions(builder);
            appendCompressions(builder);
            appendSignatureAndHashAlgorithms(builder);
            appendNamedGroups(builder);
            appendServerChoiceEnforcement(builder);
            appendExtensions(builder);
            appendCertificate(builder, ConnectionEndType.SERVER);
            appendCertificate(builder, ConnectionEndType.CLIENT);
            appendAuthBypassTest(builder);
            if (!report.getPostDtlsReports().isEmpty()) {
                appendPostDtlsTests(builder);
            }
            appendConnectionCreationReport(builder);
            appendObservedProtocols(builder);
            appendSeenFingerprints(builder);
            appendSeenCookies(builder);
            appendSeenConnectionWitnesses(builder);
            return builder.toString();
        }
    }

    private void appendTestProperties(StringBuilder builder) {
        prettyAppend(builder, "Functional", WebRtcProperties.COMPLETELY_FUNCTIONAL);
        prettyAppend(builder, "- Client functional", WebRtcProperties.CLIENT_FUNCTIONAL);
        prettyAppend(builder, "- Server functional", WebRtcProperties.SERVER_FUNCTIONAL);
        prettyAppend(
                builder,
                "Browser acts as client:",
                WebRtcProperties.INBOUND_WAS_CLIENT_NEGOTIATION);
        prettyAppend(
                builder,
                "Client Hello Direction Consistent",
                WebRtcProperties.CLIENT_HELLO_DIRECTION_CONSISTENT);
        prettyAppend(
                builder,
                "Inbound Client Hello Fingerprints",
                WebRtcProperties.INBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Inbound Server Hello Fingerprints",
                WebRtcProperties.INBOUND_SERVER_HELLO_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Outbound Client Hello Fingerprints",
                WebRtcProperties.OUTBOUND_CLIENT_HELLO_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Outbound Server Hello Fingerprints",
                WebRtcProperties.OUTBOUND_SERVER_HELLO_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Inbound Server Certificate Fingerprints",
                WebRtcProperties.INBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Outbound Server Certificate Fingerprints",
                WebRtcProperties.OUTBOUND_SERVER_CERTIFICATE_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Inbound Client Certificate Fingerprints",
                WebRtcProperties.INBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER);
        prettyAppend(
                builder,
                "Outbound Client Certificate Fingerprints",
                WebRtcProperties.OUTBOUND_CLIENT_CERTIFICATE_FINGERPRINT_COUNTER);
    }

    private void appendSeenConnectionWitnesses(StringBuilder builder) {
        prettyAppendHeading(builder, "Connection Witnesses");
        prettyAppendSubheading(builder, "Local Client Hello Witnesses");
        for (Pair<ClientHelloMessage, ConnectionInterface> witness :
                report.getLocalClientHelloWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3FingerprintString);
        }
        prettyAppendSubheading(builder, "Remote Client Hello Witnesses");
        for (Pair<ClientHelloMessage, ConnectionInterface> witness :
                report.getRemoteClientHelloWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3FingerprintString);
        }
        prettyAppendSubheading(builder, "Local Server Hello Witnesses");
        for (Pair<ServerHelloMessage, ConnectionInterface> witness :
                report.getLocalServerHelloWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3sFingerprintString);
        }
        prettyAppendSubheading(builder, "Remote Server Hello Witnesses");
        for (Pair<ServerHelloMessage, ConnectionInterface> witness :
                report.getRemoteServerHelloWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3sFingerprintString);
        }
        prettyAppendSubheading(builder, "Local Server Certificate Witnesses");
        for (Pair<CertificateMessage, ConnectionInterface> witness :
                report.getLocalServerCertificateWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3CertFingerprintString);
        }
        prettyAppendSubheading(builder, "Remote Server Certificate Witnesses");
        for (Pair<CertificateMessage, ConnectionInterface> witness :
                report.getRemoteServerCertificateWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3CertFingerprintString);
        }
        prettyAppendSubheading(builder, "Local Client Certificate Witnesses");
        for (Pair<CertificateMessage, ConnectionInterface> witness :
                report.getLocalClientCertificateWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3CertFingerprintString);
        }
        prettyAppendSubheading(builder, "Remote Client Certificate Witnesses");
        for (Pair<CertificateMessage, ConnectionInterface> witness :
                report.getRemoteClientCertificateWitnessList()) {
            appendConnectionWitness(
                    builder, witness, JaFingerprintCalculator::getJa3CertFingerprintString);
        }
    }

    private <T, R> void appendConnectionWitness(
            StringBuilder builder,
            Pair<T, ConnectionInterface> witness,
            Function<T, R> witnessTransformation) {
        try {
            prettyAppend(
                    builder,
                    witnessTransformation.apply(witness.getLeft())
                            + " - "
                            + witness.getRight().toString());
        } catch (Exception e) {
            LOGGER.error(e);
            prettyAppend(builder, "ERROR: " + e.getMessage());
        }
    }

    /**
     * @param builder
     */
    private void appendSeenFingerprints(StringBuilder builder) {
        prettyAppendHeading(builder, "Fingerprinting Results");
        prettyAppendSubheading(builder, "Remote JA3 Client's seen");
        for (String fingerprint : report.getJa3RemoteClientStringSet()) {
            prettyAppend(builder, fingerprint);
        }
        prettyAppendSubheading(builder, "Local JA3 Client's seen");
        for (String fingerprint : report.getJa3LocalClientStringSet()) {
            prettyAppend(builder, fingerprint);
        }
        prettyAppendSubheading(builder, "Remote JA3s Server's seen");
        for (String fingerprint : report.getJa3sRemoteServerStringSet()) {
            prettyAppend(builder, fingerprint);
        }
        prettyAppendSubheading(builder, "Local JA3s Server's seen");
        for (String fingerprint : report.getJa3sLocalServerStringSet()) {
            prettyAppend(builder, fingerprint);
        }
    }

    private void appendSeenCookies(StringBuilder builder) {
        prettyAppendHeading(builder, "Seen Cookies");
        prettyAppendSubheading(builder, "Locally Issued Cookies");
        for (Pair<byte[], ConnectionInterface> cookie : report.getLocalCookieWitnessList()) {
            prettyAppend(
                    builder,
                    ArrayConverter.bytesToHexString(cookie.getLeft())
                            + " - "
                            + cookie.getRight().toString());
        }
        prettyAppendSubheading(builder, "Remotely Issued Cookies");
        for (Pair<byte[], ConnectionInterface> cookie : report.getRemoteCookieWitnessList()) {
            prettyAppend(
                    builder,
                    ArrayConverter.bytesToHexString(cookie.getLeft())
                            + " - "
                            + cookie.getRight().toString());
        }
    }

    private void appendGenericProperties(StringBuilder builder) {
        prettyAppend(
                builder,
                "Server requests certificate",
                WebRtcProperties.SERVER_REQUESTS_CERTIFICATE);
        prettyAppend(
                builder, "Server Sends HVR", WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST);
        prettyAppend(
                builder, "Server issues SessionID's", WebRtcProperties.SERVER_ISSUES_SESSION_IDS);
        prettyAppend(
                builder, "Session Restart Functional", WebRtcProperties.SESSION_RESTART_FUNCTIONAL);

        if (report.getResult(WebRtcProperties.SERVER_SENDS_HELLO_VERIFY_REQUEST)
                == TestResults.TRUE) {
            prettyAppend(builder, "Example Cookie", WebRtcProperties.HVR_EXAMPLE_COOKIE);
        }
    }

    private void appendServerChoiceEnforcement(StringBuilder builder) {
        prettyAppendHeading(builder, "Server Choice Enforcement");
        prettyAppend(
                builder,
                "Cipher Suites",
                WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_CIPHER_SUITES);
        prettyAppend(
                builder, "Named Groups", WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_NAMED_GROUPS);
        prettyAppend(
                builder,
                "SKE SigHash Algorithms",
                WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_SKE_SIG_HASH_ALGORITHMS);
        prettyAppend(
                builder,
                "SRTP Protection Profile",
                WebRtcProperties.SERVER_ENFORCES_PICK_ORDER_SRTP_PROTECTION_PROFILE);
    }

    private void appendProtocolVersions(StringBuilder builder) {
        prettyAppendHeading(builder, "Supported Versions");
        prettyAppend(
                builder,
                "Client DTLS 1.0",
                report.getResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_0).getName());
        prettyAppend(
                builder,
                "Client DTLS 1.2",
                report.getResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_2).getName());
        prettyAppend(
                builder,
                "Client DTLS 1.3",
                report.getResult(WebRtcProperties.CLIENT_SUPPORTS_DTLS_1_3).getName());
        prettyAppend(
                builder,
                "Server DTLS 1.0",
                report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_0).getName());
        prettyAppend(
                builder,
                "Server DTLS 1.2",
                report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_2).getName());
        prettyAppend(
                builder,
                "Server DTLS 1.3",
                report.getResult(WebRtcProperties.SERVER_SUPPORTS_DTLS_1_3).getName());
    }

    private StringBuilder appendNamedGroups(StringBuilder builder) {
        if (report.getClientSupportedNamedGroups() != null) {
            prettyAppendHeading(builder, "Client Named Groups");
            for (NamedGroup namedGroup : report.getClientSupportedNamedGroups()) {
                builder.append(namedGroup.name()).append("\n");
            }
        }

        if (report.getServerSupportedNamedGroups() != null) {
            prettyAppendHeading(
                    builder,
                    "Server Named Groups - Definite: "
                            + report.getResult(
                                    WebRtcProperties
                                            .SERVER_NAMED_GROUP_SCAN_TERMINATION_SYMBOL_SEEN));
            for (NamedGroup namedGroup : report.getServerSupportedNamedGroups()) {
                builder.append(namedGroup.name()).append("\n");
            }
        }
        return builder;
    }

    private void appendSrtpMKI(StringBuilder builder) {
        prettyAppendHeading(builder, "SRTP MKI");
        prettyAppend(
                builder,
                "Client sends MKI",
                report.getResult(WebRtcProperties.CLIENT_SENDS_SRTP_MKI).getName());
        prettyAppend(
                builder,
                "Server accepts single MKI byte",
                report.getResult(WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_SINGLE_BYTE).getName());
        prettyAppend(
                builder,
                "Server accepts two MKI bytes",
                report.getResult(WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_TWO_BYTES).getName());
        prettyAppend(
                builder,
                "Server accepts three MKI bytes",
                report.getResult(WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_THREE_BYTES).getName());
        prettyAppend(
                builder,
                "Server accepts four MKI bytes",
                report.getResult(WebRtcProperties.SERVER_ACCEPTS_SRTP_MKI_FOUR_BYTES).getName());
        prettyAppend(
                builder,
                "Example MKI",
                report.getResult(WebRtcProperties.EXAMPLE_SRTP_MKI_VALUE).getName());
    }

    public StringBuilder appendExtensions(StringBuilder builder) {
        if (report.getClientSupportedExtensions() != null) {
            prettyAppendHeading(builder, "Client Supported Extensions");
            for (ExtensionType type : report.getClientSupportedExtensions()) {
                builder.append(type.name()).append("\n");
            }
        }

        if (report.getServerSupportedExtensions() != null) {
            prettyAppendHeading(builder, "Server Supported Extensions");
            for (ExtensionType type : report.getServerSupportedExtensions()) {
                builder.append(type.name()).append("\n");
            }
        }

        if (report.getNegotiatedExtensions() != null) {
            prettyAppendHeading(builder, "Negotiated Extensions");
            for (ExtensionType type : report.getNegotiatedExtensions()) {
                builder.append(type.name()).append("\n");
            }
        }
        return builder;
    }

    public StringBuilder appendCipherSuites(StringBuilder builder) {
        if (report.getClientSupportedCipherSuites() != null) {
            prettyAppendHeading(builder, "Client Cipher Suites");
            for (CipherSuite suite : report.getClientSupportedCipherSuites()) {
                builder.append(suite.name()).append("\n");
            }
        }

        if (report.getServerSupportedCipherSuites() != null) {
            prettyAppendHeading(
                    builder,
                    "Server Cipher Suites - Definite: "
                            + report.getResult(
                                    WebRtcProperties
                                            .SERVER_CIPHERSUITE_SCAN_TERMINATION_SYMBOL_SEEN));
            for (CipherSuite suite : report.getServerSupportedCipherSuites()) {
                if (report.getFunctionalServerSupportedCipherSuites() != null) {
                    if (report.getFunctionalServerSupportedCipherSuites().contains(suite)) {
                        builder.append(suite.name()).append("\t\t\t(functional)\n");
                    } else {
                        builder.append(suite.name()).append("\t\t\t(broken!)\n");
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendCompressions(StringBuilder builder) {
        if (report.getClientSupportedCompressionMethods() != null) {
            prettyAppendHeading(builder, "Client Compression Methods");
            for (CompressionMethod compression : report.getClientSupportedCompressionMethods()) {
                builder.append(compression.name()).append("\n");
            }
        }

        if (report.getServerSupportedCompressionMethods() != null) {
            prettyAppendHeading(builder, "Server Compression Methods");
            for (CompressionMethod compression : report.getServerSupportedCompressionMethods()) {
                builder.append(compression.name()).append("\n");
            }
        }
        return builder;
    }

    public StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
        if (report.getClientSupportedSignatureAndHashAlgorithms() != null) {
            prettyAppendHeading(builder, "Client Signature and Hash Algorithms");
            for (SignatureAndHashAlgorithm signatureAndHashAlgorithm :
                    report.getClientSupportedSignatureAndHashAlgorithms()) {
                builder.append(signatureAndHashAlgorithm.name()).append("\n");
            }
        }

        if (report.getServerSupportedSignatureAndHashAlgorithms() != null) {
            prettyAppendHeading(
                    builder,
                    "Server Signature and Hash Algorithms: Definite: "
                            + report.getResult(
                                    WebRtcProperties
                                            .SERVER_SIGNATURE_AND_HASH_ALGORITHM_SCAN_TERMINATION_SYMBOL_SEEN));
            for (SignatureAndHashAlgorithm signatureAndHashAlgorithm :
                    report.getServerSupportedSignatureAndHashAlgorithms()) {
                builder.append(signatureAndHashAlgorithm.name()).append("\n");
            }
        }

        if (report.getServerRequestedSignatureAndHashAlgorithms() != null) {
            prettyAppendHeading(builder, "Server Requested Signature and Hash Algorithms");
            for (SignatureAndHashAlgorithm signatureAndHashAlgorithm :
                    report.getServerRequestedSignatureAndHashAlgorithms()) {
                builder.append(signatureAndHashAlgorithm.name()).append("\n");
            }
        }
        return builder;
    }

    private StringBuilder appendDefaultSelected(StringBuilder builder) {
        // We are checking the default selected cipher suite as a representative that
        // the data was collectable
        if (report.getDefaultSelectedCipherSuite() != null) {
            prettyAppendHeading(builder, "Default Selection");
            prettyAppend(
                    builder, "Default cipher suite", report.getDefaultSelectedCipherSuite().name());
            if (report.getDefaultSelectedProtocolVersion() != null) {
                prettyAppend(
                        builder,
                        "Default protocol version",
                        report.getDefaultSelectedProtocolVersion().name());
            }

            if (report.getDefaultSelectedCompressionMethod() != null) {
                prettyAppend(
                        builder,
                        "Default compression method",
                        report.getDefaultSelectedCompressionMethod().name());
            }

            if (report.getDefaultSelectedSrtpProtectionProfile() != null) {
                prettyAppend(
                        builder,
                        "Default SRTP protection profile",
                        report.getDefaultSelectedSrtpProtectionProfile().name());
            }
            if (report.getDefaultSelectedNamedGroup() != null) {
                prettyAppend(
                        builder,
                        "Default Named Group",
                        report.getDefaultSelectedNamedGroup().name());
            }
            if (report.getDefaultClientSelectedSignatureAndHashAlgorithm() != null) {
                prettyAppend(
                        builder,
                        "Default Client Selected SigHashAlgo",
                        report.getDefaultClientSelectedSignatureAndHashAlgorithm().name());
            }
            if (report.getDefaultServerSelectedSignatureAndHashAlgorithm() != null) {
                prettyAppend(
                        builder,
                        "Default Server Selected SigHashAlgo",
                        report.getDefaultServerSelectedSignatureAndHashAlgorithm().name());
            }
        }
        return builder;
    }

    private StringBuilder appendConnectionCreationReport(StringBuilder builder) {
        prettyAppendHeading(builder, "Connection Statistics");
        if (report.getConnectionCreationReport() != null) {
            prettyAppend(
                    builder,
                    "#Connections",
                    report.getConnectionCreationReport().getNumberOfConnections());
            prettyAppend(
                    builder,
                    "#DifferentLocalPorts",
                    report.getConnectionCreationReport().getNumberOfDifferentLocalPorts());
            prettyAppend(
                    builder,
                    "#DifferentRemotePorts",
                    report.getConnectionCreationReport().getNumberOfDifferentRemotePorts());
            prettyAppend(
                    builder,
                    "#DifferentTurnMappedAddresses",
                    report.getConnectionCreationReport().getNumberOfDifferentTurnMappedAddresses());
            prettyAppend(
                    builder,
                    "#DifferentTurnMappedPorts",
                    report.getConnectionCreationReport().getNumberOfDifferentTurnMappedPorts());
            prettyAppend(
                    builder,
                    "#OutboundServerCon.",
                    report.getConnectionCreationReport().getNumberOfInboundClientConnections());
            prettyAppend(
                    builder,
                    "#InboundServerCon.",
                    report.getConnectionCreationReport().getNumberOfInboundServerConnections());
            prettyAppend(
                    builder,
                    "#PlainConnections",
                    report.getConnectionCreationReport().getNumberOfPlainConnections());
            prettyAppend(
                    builder,
                    "#TotalTurnMappedCon.",
                    report.getConnectionCreationReport().getNumberOfTotalTurnMappedConnections());
            prettyAppend(
                    builder,
                    "#TurnConnections",
                    report.getConnectionCreationReport().getNumberOfTurnConnections());
        }
        prettyAppend(builder, "\nDTLS Connections per Call", report.getDtlsSessionsPerCall());

        return builder;
    }

    private StringBuilder appendCertificate(
            StringBuilder builder, ConnectionEndType connectionEndType) {

        X509CertificateChain chain;
        if (connectionEndType == ConnectionEndType.CLIENT) {
            chain = report.getExampleClientCertificateChain();
        } else {
            chain = report.getExampleServerCertificateChain();
        }
        if (chain != null) {
            CertificateChainReport chainReport =
                    new CertificateChainReport(chain, report.getTargetName());
            final WebRtcProperties propertyStaticCert =
                    connectionEndType == ConnectionEndType.CLIENT
                            ? WebRtcProperties.STATIC_CLIENT_CERTIFICATE
                            : WebRtcProperties.STATIC_SERVER_CERTIFICATE;

            prettyAppendHeading(builder, connectionEndType.name() + " Certificate Chain");
            prettyAppend(builder, "Static Certificate", propertyStaticCert);
            if (report.getResult(propertyStaticCert) == TestResults.FALSE) {
                prettyAppendSubheading(builder, "Example Certificate");
            } else {
                prettyAppendSubheading(builder, "Static Certificate");
            }
            prettyAppend(
                    builder,
                    "Chain ordered",
                    chainReport.getChainIsOrdered(),
                    Objects.equals(chainReport.getChainIsOrdered(), Boolean.TRUE)
                            ? AnsiColor.GREEN
                            : AnsiColor.YELLOW);
            prettyAppend(
                    builder,
                    "Contains Trust Anchor",
                    chainReport.getContainsTrustAnchor(),
                    Objects.equals(chainReport.getContainsTrustAnchor(), Boolean.TRUE)
                            ? AnsiColor.RED
                            : AnsiColor.GREEN);
            prettyAppend(
                    builder,
                    "Generally Trusted",
                    chainReport.getGenerallyTrusted(),
                    Objects.equals(chainReport.getGenerallyTrusted(), Boolean.TRUE)
                            ? AnsiColor.GREEN
                            : AnsiColor.RED);

            if (!chainReport.getCertificateReportList().isEmpty()) {
                for (int i = 0; i < chainReport.getCertificateReportList().size(); i++) {
                    CertificateReport certReport = chainReport.getCertificateReportList().get(i);
                    prettyAppendSubheading(builder, "Certificate #" + (i + 1));

                    if (certReport.getSubject() != null) {
                        prettyAppend(builder, "Subject", certReport.getSubject());
                    }

                    if (certReport.getIssuer() != null) {
                        prettyAppend(builder, "Issuer", certReport.getIssuer());
                    }
                    if (certReport.getNotBefore() != null) {
                        if (certReport.getNotBefore().isBeforeNow()) {
                            prettyAppend(
                                    builder,
                                    "Valid From",
                                    certReport.getNotBefore().toString(),
                                    AnsiColor.GREEN);
                        } else {
                            prettyAppend(
                                    builder,
                                    "Valid From",
                                    certReport.getNotBefore().toString() + " - NOT YET VALID",
                                    AnsiColor.RED);
                        }
                    }
                    if (certReport.getNotAfter() != null) {
                        if (certReport.getNotAfter().isAfterNow()) {
                            prettyAppend(
                                    builder,
                                    "Valid Till",
                                    certReport.getNotAfter().toString(),
                                    AnsiColor.GREEN);
                        } else {
                            prettyAppend(
                                    builder,
                                    "Valid Till",
                                    certReport.getNotAfter().toString() + " - EXPIRED",
                                    AnsiColor.RED);
                        }
                    }
                    if (certReport.getNotBefore() != null
                            && certReport.getNotAfter() != null
                            && certReport.getNotAfter().isAfterNow()) {
                        int days =
                                Days.daysBetween(DateTime.now(), certReport.getNotAfter())
                                        .getDays();
                        if (days < 1) {
                            prettyAppend(
                                    builder,
                                    "Expires in",
                                    "<1 day! This certificate expires very soon",
                                    AnsiColor.RED);
                        } else if (days < 3) {
                            prettyAppend(
                                    builder,
                                    "Expires in",
                                    days + " days! This certificate expires soon",
                                    AnsiColor.RED);
                        } else if (days < 14) {
                            prettyAppend(
                                    builder,
                                    "Expires in",
                                    days + " days. This certificate expires soon",
                                    AnsiColor.YELLOW);
                        } else if (days < 31) {
                            prettyAppend(
                                    builder,
                                    "Expires in",
                                    days + " days.",
                                    AnsiColor.DEFAULT_COLOR);
                        } else if (days < 730) {
                            prettyAppend(builder, "Expires in", days + " days.", AnsiColor.GREEN);
                        } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                            prettyAppend(
                                    builder,
                                    "Expires in",
                                    days + " days. This is usually too long for a leaf certificate",
                                    AnsiColor.RED);
                        } else {
                            prettyAppend(
                                    builder, "Expires in", days / 365 + " years", AnsiColor.GREEN);
                        }
                    }
                    if (certReport.getPublicKey() != null) {
                        prettyAppendPublicKey(builder, certReport.getPublicKey());
                    }
                    if (certReport.getWeakDebianKey() != null) {
                        prettyAppend(
                                builder,
                                "Weak Debian Key",
                                certReport.getWeakDebianKey(),
                                certReport.getWeakDebianKey() ? AnsiColor.RED : AnsiColor.GREEN);
                    }
                    if (certReport.getSignatureAlgorithm() != null) {
                        prettyAppend(
                                builder,
                                "Signature Algorithm",
                                certReport.getSignatureAlgorithm().name());
                    }
                    if (certReport.getSignatureAlgorithm() != null) {
                        if (certReport.getHashAlgorithm() == HashAlgorithm.SHA1
                                || certReport.getHashAlgorithm() == HashAlgorithm.MD5) {
                            if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                                prettyAppend(
                                        builder,
                                        "Hash Algorithm",
                                        certReport.getHashAlgorithm().name(),
                                        AnsiColor.RED);
                            } else {
                                prettyAppend(
                                        builder,
                                        "Hash Algorithm",
                                        certReport.getHashAlgorithm().name() + " - Not critical");
                            }
                        } else {
                            prettyAppend(
                                    builder,
                                    "Hash Algorithm",
                                    certReport.getHashAlgorithm().name(),
                                    AnsiColor.GREEN);
                        }
                    }
                    if (certReport.getExtendedValidation() != null) {
                        prettyAppend(
                                builder,
                                "Extended Validation",
                                certReport.getExtendedValidation(),
                                certReport.getExtendedValidation()
                                        ? AnsiColor.GREEN
                                        : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getCertificateTransparency() != null) {
                        prettyAppend(
                                builder,
                                "Certificate Transparency",
                                certReport.getCertificateTransparency(),
                                certReport.getCertificateTransparency()
                                        ? AnsiColor.GREEN
                                        : AnsiColor.YELLOW);
                    }

                    if (certReport.getCrlSupported() != null) {
                        prettyAppend(
                                builder,
                                "CRL Supported",
                                certReport.getCrlSupported(),
                                certReport.getCrlSupported()
                                        ? AnsiColor.GREEN
                                        : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getOcspSupported() != null) {
                        prettyAppend(
                                builder,
                                "OCSP Supported",
                                certReport.getOcspSupported(),
                                certReport.getOcspSupported() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                    }
                    if (certReport.getOcspMustStaple() != null) {
                        prettyAppend(builder, "OCSP must Staple", certReport.getOcspMustStaple());
                    }
                    if (certReport.getRevoked() != null) {
                        prettyAppend(
                                builder,
                                "RevocationStatus",
                                certReport.getRevoked(),
                                certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN);
                    }
                    if (certReport.getDnsCAA() != null) {
                        prettyAppend(
                                builder,
                                "DNS CCA",
                                certReport.getDnsCAA(),
                                certReport.getDnsCAA() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                    }
                    if (certReport.getRocaVulnerable() != null) {
                        prettyAppend(
                                builder,
                                "ROCA (simple)",
                                certReport.getRocaVulnerable(),
                                certReport.getRocaVulnerable() ? AnsiColor.RED : AnsiColor.GREEN);
                    } else {
                        builder.append("ROCA (simple): not tested");
                    }
                    prettyAppendHexString(
                            builder,
                            "Fingerprint (SHA256)",
                            ArrayConverter.bytesToHexString(
                                    certReport.getSHA256Fingerprint(), false, false));
                }
            }
        }
        return builder;
    }

    private String prettyAppendPublicKey(StringBuilder builder, PublicKeyContainer publicKey) {
        if (publicKey instanceof DhPublicKey) {
            DhPublicKey dhPublicKey = (DhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "Static Diffie Hellman");

            prettyAppendHexString(builder, "Modulus", dhPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Generator", dhPublicKey.getGenerator().toString(16));
            prettyAppendHexString(builder, "Y", dhPublicKey.getPublicKey().toString(16));
        } else if (publicKey instanceof DsaPublicKey) {
            DsaPublicKey dsaPublicKey = (DsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "DSA");
            prettyAppendHexString(builder, "Modulus", dsaPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Generator", dsaPublicKey.getGenerator().toString(16));
            prettyAppendHexString(builder, "Q", dsaPublicKey.getQ().toString(16));
            prettyAppendHexString(builder, "X", dsaPublicKey.getY().toString(16));
        } else if (publicKey instanceof RsaPublicKey) {
            RsaPublicKey rsaPublicKey = (RsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "RSA");
            prettyAppendHexString(builder, "Modulus", rsaPublicKey.getModulus().toString(16));
            prettyAppendHexString(
                    builder, "Public exponent", rsaPublicKey.getPublicExponent().toString(16));
        } else if (publicKey instanceof EcdhPublicKey) {
            EcdhPublicKey ecdhPublicKey = (EcdhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "ECDH");
            prettyAppend(builder, "Group", ecdhPublicKey.getParameters().name());
            prettyAppendHexString(
                    builder, "Public Point", ecdhPublicKey.getPublicPoint().toString());
        } else if (publicKey instanceof EcdsaPublicKey) {
            EcdsaPublicKey ecdsaPublicKey = (EcdsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "ECDH/ECDSA");
            prettyAppend(builder, "Group", ecdsaPublicKey.getParameters().name());
            prettyAppendHexString(
                    builder, "Public Point", ecdsaPublicKey.getPublicPoint().toString());
        } else {
            builder.append(publicKey.toString()).append("\n");
        }
        return builder.toString();
    }

    private StringBuilder appendSrtpProtectionProfiles(StringBuilder builder) {
        if (report.getClientSupportedProtectionProfiles() != null) {
            prettyAppendHeading(builder, "Client Supported SRTP Protection Profiles");
            for (SrtpProtectionProfile profile : report.getClientSupportedProtectionProfiles()) {
                builder.append(profile.name()).append("\n");
            }
        }
        if (report.getServerSupportedProtectionProfiles() != null) {
            prettyAppendHeading(
                    builder,
                    "Server Supported SRTP Protection Profiles  - Definite: "
                            + report.getResult(
                                    WebRtcProperties.SERVER_SRTP_SCAN_TERMINATION_SYMBOL_SEEN));
            for (SrtpProtectionProfile profile : report.getServerSupportedProtectionProfiles()) {
                builder.append(profile.name()).append("\n");
            }
        }

        return builder;
    }

    private StringBuilder appendAuthBypassTest(StringBuilder builder) {
        prettyAppendHeading(builder, "Authentication Bypasses");
        prettyAppendSubheading(builder, "Client");
        prettyAppend(
                builder, "Verifies Certificates", WebRtcProperties.CLIENT_VERIFIES_CERTIFICATE);
        prettyAppend(
                builder,
                "Rejects Provided Certificate",
                WebRtcProperties.CLIENT_REJECTS_PROVIDED_CERTIFICATE);
        prettyAppend(builder, "Notices empty CERT", WebRtcProperties.CLIENT_NOTICES_EMPTY_CERT);
        prettyAppend(
                builder,
                "Enforces Client Auth.",
                WebRtcProperties.CLIENT_ENFORCES_CLIENT_AUTHENTICATION);
        prettyAppend(
                builder,
                "Notices invalid SKE sign.",
                WebRtcProperties.CLIENT_VERIFIES_SKE_SIGNATURE);
        prettyAppend(
                builder,
                "Notices empty SKE sign.",
                WebRtcProperties.CLIENT_NOTICES_EMPTY_SKE_SIGNATURE);
        prettyAppend(
                builder,
                "Notices missing SKE sign.",
                WebRtcProperties.CLIENT_NOTICES_MISSING_SKE_SIGNATURE);
        prettyAppend(
                builder,
                "Not Processing Double SKE (same SQN)",
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_SAME_SQN);
        prettyAppend(
                builder,
                "Not Processing Double SKE (cont. SQN)",
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_SKE_CONTINUOUS_SQN);
        prettyAppend(
                builder,
                "Rejects mimicry cert",
                WebRtcProperties.CLIENT_REJECTS_MIMICRY_CERTIFICATE);
        prettyAppend(
                builder,
                "Rejects double leaf trick (A,R)",
                WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL);
        prettyAppend(
                builder,
                "Rejects double leaf trick (R,A)",
                WebRtcProperties.CLIENT_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER);
        prettyAppend(
                builder,
                "Rejects corrupted certificate",
                WebRtcProperties.CLIENT_REJECTS_CORRUPTED_CERTIFICATE);

        prettyAppendSubheading(builder, "Server");

        prettyAppend(builder, "No Early ID Resumption", WebRtcProperties.NO_EARLY_RESUMPTION_IDS);
        prettyAppend(
                builder, "Verifies Certificates", WebRtcProperties.SERVER_VERIFIES_CERTIFICATE);

        prettyAppend(
                builder,
                "Rejects Provided Certificate",
                WebRtcProperties.SERVER_REJECTS_PROVIDED_CERTIFICATE);

        prettyAppend(builder, "Notices missing CV", WebRtcProperties.SERVER_NOTICES_MISSING_CV);
        prettyAppend(
                builder,
                "Notices missing CERT (empty CV)",
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_EMPTY_SIGNATURE);
        prettyAppend(
                builder,
                "Notices missing CERT (0x00 CV)",
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_ALL_ZERO_SIGNATURE);
        prettyAppend(
                builder,
                "Notices missing CERT (0xFF CV)",
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_ALL_FF_SIGNATURE);
        prettyAppend(
                builder,
                "Notices missing CERT,CV",
                WebRtcProperties.SERVER_NOTICES_MISSING_CERT_CV);
        prettyAppend(builder, "Notices empty CERT", WebRtcProperties.SERVER_NOTICES_EMPTY_CERT);

        prettyAppend(
                builder, "Notices invalid CV sign.", WebRtcProperties.SERVER_VERIFIES_CV_SIGNATURE);
        prettyAppend(
                builder,
                "Notices empty CV sign.",
                WebRtcProperties.SERVER_NOTICES_EMPTY_CV_SIGNATURE);
        prettyAppend(
                builder,
                "Notices missing CV sign",
                WebRtcProperties.SERVER_NOTICES_MISSING_CV_SIGNATURE);

        prettyAppend(
                builder,
                "Not Processing Double CKE (same SQN)",
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_SAME_SQN);
        prettyAppend(
                builder,
                "Not Processing Double CKE (cont. SQN)",
                WebRtcProperties.NOT_PROCESSING_UNAUTHENTICATED_DOUBLE_CKE_CONTINUOUS_SQN);
        prettyAppend(
                builder,
                "Rejects mimicry cert",
                WebRtcProperties.SERVER_REJECTS_MIMICRY_CERTIFICATE);
        prettyAppend(
                builder,
                "Rejects double leaf trick (A,R)",
                WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_ATTACKER_REAL);
        prettyAppend(
                builder,
                "Rejects double leaf trick (R,A)",
                WebRtcProperties.SERVER_REJECTS_DOUBLE_LEAF_TRICK_REAL_ATTACKER);
        prettyAppend(
                builder,
                "Rejects corrupted certificate",
                WebRtcProperties.SERVER_REJECTS_CORRUPTED_CERTIFICATE);
        return builder;
    }

    private StringBuilder appendObservedProtocols(StringBuilder builder) {

        if (report.getProtocolsObservedInbound() == null
                && report.getProtocolsObservedOutbound() == null) {
            return builder;
        }

        prettyAppendHeading(builder, "Observed protocols, average packet count per interval");

        if (report.getProtocolsObservedInbound() != null
                && !report.getProtocolsObservedInbound().isEmpty()) {
            builder.append("From inbound:\n");
            for (PacketType type : report.getProtocolsObservedInbound().keySet()) {
                builder.append("\t")
                        .append(type.name())
                        .append(": ")
                        .append(report.getProtocolsObservedInbound().get(type))
                        .append("\n");
            }
        }

        if (report.getProtocolsObservedOutbound() != null
                && !report.getProtocolsObservedOutbound().isEmpty()) {
            builder.append("From outbound:\n");
            for (PacketType type : report.getProtocolsObservedOutbound().keySet()) {
                builder.append("\t")
                        .append(type.name())
                        .append(": ")
                        .append(report.getProtocolsObservedOutbound().get(type))
                        .append("\n");
            }
        }

        return builder;
    }

    private StringBuilder appendPostDtlsTests(StringBuilder builder) {
        prettyAppendHeading(builder, "Post DTLS");

        for (MediaReport mediaReport : report.getPostDtlsReports()) {

            String heading =
                    mediaReport.getLabel()
                            + (mediaReport.isTestable()
                                    ? ", " + mediaReport.getBypassUsed().getDescription()
                                    : "");

            prettyAppendSubheading(builder, heading);

            if (!mediaReport.isTestable() || mediaReport.getBypassUsed() == null) {
                prettyAppend(builder, "Not testable");
                continue;
            }

            for (WebRtcProperties additionalResult : mediaReport.getAdditionalResults().keySet()) {
                builder.append(additionalResult.name())
                        .append(": ")
                        .append(mediaReport.getAdditionalResults().get(additionalResult).getName())
                        .append("\n");
            }

            if (!mediaReport.isDtlsHandshakeSuccess()) {
                prettyAppend(builder, "DTLS MitM handshake fail\n");
                continue;
            }

            for (MediaProtocol protocol : MediaProtocol.values()) {

                final boolean haveResultsClientToServer =
                        mediaReport.getResultsClientToServer().containsKey(protocol);
                final boolean haveResultsServerToClient =
                        mediaReport.getResultsServerToClient().containsKey(protocol);

                if (!haveResultsClientToServer && !haveResultsServerToClient) {
                    continue;
                }

                if (haveResultsClientToServer) {
                    for (MitmProperties property : MitmProperties.values()) {
                        if (mediaReport.getResultsClientToServer().get(protocol).get(property)
                                != null) {
                            builder.append("[client -> server] ")
                                    .append(protocol.name())
                                    .append("\t")
                                    .append(property.name())
                                    .append(":\t")
                                    .append(
                                            mediaReport
                                                    .getResultsClientToServer()
                                                    .get(protocol)
                                                    .get(property))
                                    .append("\n");
                        }
                    }
                }

                if (haveResultsServerToClient) {
                    for (MitmProperties property : MitmProperties.values()) {
                        if (mediaReport.getResultsServerToClient().get(protocol).get(property)
                                != null) {
                            builder.append("[server -> client] ")
                                    .append(protocol.name())
                                    .append("\t")
                                    .append(property.name())
                                    .append(":\t")
                                    .append(
                                            mediaReport
                                                    .getResultsServerToClient()
                                                    .get(protocol)
                                                    .get(property))
                                    .append("\n");
                        }
                    }
                }
            }
            builder.append("\n");
        }

        return builder;
    }
}
