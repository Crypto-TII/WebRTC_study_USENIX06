/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.report;

import de.rub.nds.dtlsproxy.enums.FilterDirection;
import de.rub.nds.dtlsproxy.enums.PacketType;
import de.rub.nds.dtlsproxy.provider.ConnectionInterface;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.tuple.Pair;

public class WebRtcPlatformReport extends ScanReport {

    private final String targetName;
    private final FilterDirection lockedFilterDirection;

    private ProtocolVersion defaultSelectedProtocolVersion;
    private CipherSuite defaultSelectedCipherSuite;
    private CompressionMethod defaultSelectedCompressionMethod;
    private SrtpProtectionProfile defaultSelectedSrtpProtectionProfile;
    private SignatureAndHashAlgorithm defaultServerSelectedSignatureAndHashAlgorithm;
    private SignatureAndHashAlgorithm defaultClientSelectedSignatureAndHashAlgorithm;
    private NamedGroup defaultSelectedNamedGroup;

    private List<CipherSuite> clientSupportedCipherSuites;
    private List<CompressionMethod> clientSupportedCompressionMethods;
    private List<CipherSuite> serverSupportedCipherSuites;
    private List<CipherSuite> functionalServerSupportedCipherSuites;
    private List<NamedGroup> serverSupportedNamedGroups;
    private List<NamedGroup> clientSupportedNamedGroups;
    private List<CompressionMethod> serverSupportedCompressionMethods;
    private List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms;
    private List<SignatureAndHashAlgorithm> serverRequestedSignatureAndHashAlgorithms;
    private List<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms;

    private Set<ExtensionType> negotiatedExtensions;
    private Set<ExtensionType> clientSupportedExtensions;
    private Set<ExtensionType> serverSupportedExtensions;

    private List<SNIEntry> clientSNIEntryList;

    private List<SrtpProtectionProfile> clientSupportedProtectionProfiles;
    private List<SrtpProtectionProfile> serverSupportedProtectionProfiles;

    private X509CertificateChain exampleServerCertificateChain;
    private X509CertificateChain exampleClientCertificateChain;

    private int defaultSignatureLength;

    private List<MediaReport> postDtlsReports = new ArrayList<>();

    private ConnectionCreationReport connectionCreationReport;

    private HashMap<PacketType, Integer> protocolsObservedInbound;
    private HashMap<PacketType, Integer> protocolsObservedOutbound;

    private Set<String> ja3RemoteClientStringSet = new HashSet<>();
    private Set<String> ja3LocalClientStringSet = new HashSet<>();
    private Set<String> ja3sRemoteServerStringSet = new HashSet<>();
    private Set<String> ja3sLocalServerStringSet = new HashSet<>();

    private List<Pair<ClientHelloMessage, ConnectionInterface>> localClientHelloWitnessList =
            new LinkedList<>();
    private List<Pair<ClientHelloMessage, ConnectionInterface>> remoteClientHelloWitnessList =
            new LinkedList<>();
    private List<Pair<ServerHelloMessage, ConnectionInterface>> localServerHelloWitnessList =
            new LinkedList<>();
    private List<Pair<ServerHelloMessage, ConnectionInterface>> remoteServerHelloWitnessList =
            new LinkedList<>();

    private List<Pair<CertificateMessage, ConnectionInterface>> localClientCertificateWitnessList =
            new LinkedList<>();
    private List<Pair<CertificateMessage, ConnectionInterface>> remoteClientCertificateWitnessList =
            new LinkedList<>();
    private List<Pair<CertificateMessage, ConnectionInterface>> localServerCertificateWitnessList =
            new LinkedList<>();
    private List<Pair<CertificateMessage, ConnectionInterface>> remoteServerCertificateWitnessList =
            new LinkedList<>();

    private List<Pair<byte[], ConnectionInterface>> localCookieWitnessList = new LinkedList<>();
    private List<Pair<byte[], ConnectionInterface>> remoteCookieWitnessList = new LinkedList<>();

    private int dtlsSessionsPerCall = 1;

    public WebRtcPlatformReport(String targetName, FilterDirection lockedFilterDirection) {
        this.targetName = targetName;
        this.lockedFilterDirection = lockedFilterDirection;
    }

    public List<Pair<ClientHelloMessage, ConnectionInterface>> getLocalClientHelloWitnessList() {
        return localClientHelloWitnessList;
    }

    public void setLocalClientHelloWitnessList(
            List<Pair<ClientHelloMessage, ConnectionInterface>> localClientHelloWitnessList) {
        this.localClientHelloWitnessList = localClientHelloWitnessList;
    }

    public List<Pair<ClientHelloMessage, ConnectionInterface>> getRemoteClientHelloWitnessList() {
        return remoteClientHelloWitnessList;
    }

    public void setRemoteClientHelloWitnessList(
            List<Pair<ClientHelloMessage, ConnectionInterface>> remoteClientHelloWitnessList) {
        this.remoteClientHelloWitnessList = remoteClientHelloWitnessList;
    }

    public List<Pair<ServerHelloMessage, ConnectionInterface>> getLocalServerHelloWitnessList() {
        return localServerHelloWitnessList;
    }

    public void setLocalServerHelloWitnessList(
            List<Pair<ServerHelloMessage, ConnectionInterface>> localServerHelloWitnessList) {
        this.localServerHelloWitnessList = localServerHelloWitnessList;
    }

    public List<Pair<ServerHelloMessage, ConnectionInterface>> getRemoteServerHelloWitnessList() {
        return remoteServerHelloWitnessList;
    }

    public void setRemoteServerHelloWitnessList(
            List<Pair<ServerHelloMessage, ConnectionInterface>> remoteServerHelloWitnessList) {
        this.remoteServerHelloWitnessList = remoteServerHelloWitnessList;
    }

    public List<Pair<CertificateMessage, ConnectionInterface>>
            getLocalClientCertificateWitnessList() {
        return localClientCertificateWitnessList;
    }

    public void setLocalClientCertificateWitnessList(
            List<Pair<CertificateMessage, ConnectionInterface>> localClientCertificateWitnessList) {
        this.localClientCertificateWitnessList = localClientCertificateWitnessList;
    }

    public List<Pair<CertificateMessage, ConnectionInterface>>
            getRemoteClientCertificateWitnessList() {
        return remoteClientCertificateWitnessList;
    }

    public void setRemoteClientCertificateWitnessList(
            List<Pair<CertificateMessage, ConnectionInterface>>
                    remoteClientCertificateWitnessList) {
        this.remoteClientCertificateWitnessList = remoteClientCertificateWitnessList;
    }

    public List<Pair<CertificateMessage, ConnectionInterface>>
            getLocalServerCertificateWitnessList() {
        return localServerCertificateWitnessList;
    }

    public void setLocalServerCertificateWitnessList(
            List<Pair<CertificateMessage, ConnectionInterface>> localServerCertificateWitnessList) {
        this.localServerCertificateWitnessList = localServerCertificateWitnessList;
    }

    public List<Pair<CertificateMessage, ConnectionInterface>>
            getRemoteServerCertificateWitnessList() {
        return remoteServerCertificateWitnessList;
    }

    public void setRemoteServerCertificateWitnessList(
            List<Pair<CertificateMessage, ConnectionInterface>>
                    remoteServerCertificateWitnessList) {
        this.remoteServerCertificateWitnessList = remoteServerCertificateWitnessList;
    }

    public List<Pair<byte[], ConnectionInterface>> getLocalCookieWitnessList() {
        return localCookieWitnessList;
    }

    public void setLocalCookieWitnessList(
            List<Pair<byte[], ConnectionInterface>> localCookieWitnessList) {
        this.localCookieWitnessList = localCookieWitnessList;
    }

    public List<Pair<byte[], ConnectionInterface>> getRemoteCookieWitnessList() {
        return remoteCookieWitnessList;
    }

    public void setRemoteCookieWitnessList(
            List<Pair<byte[], ConnectionInterface>> remoteCookieWitnessList) {
        this.remoteCookieWitnessList = remoteCookieWitnessList;
    }

    public Set<String> getJa3RemoteClientStringSet() {
        return ja3RemoteClientStringSet;
    }

    public void setJa3RemoteClientStringSet(Set<String> ja3RemoteClientStringSet) {
        this.ja3RemoteClientStringSet = ja3RemoteClientStringSet;
    }

    public Set<String> getJa3LocalClientStringSet() {
        return ja3LocalClientStringSet;
    }

    public void setJa3LocalClientStringSet(Set<String> ja3LocalClientStringSet) {
        this.ja3LocalClientStringSet = ja3LocalClientStringSet;
    }

    public Set<String> getJa3sRemoteServerStringSet() {
        return ja3sRemoteServerStringSet;
    }

    public void setJa3sRemoteServerStringSet(Set<String> ja3sRemoteServerStringSet) {
        this.ja3sRemoteServerStringSet = ja3sRemoteServerStringSet;
    }

    public Set<String> getJa3sLocalServerStringSet() {
        return ja3sLocalServerStringSet;
    }

    public void setJa3sLocalServerStringSet(Set<String> ja3sLocalServerStringSet) {
        this.ja3sLocalServerStringSet = ja3sLocalServerStringSet;
    }

    public List<CipherSuite> getFunctionalServerSupportedCipherSuites() {
        return functionalServerSupportedCipherSuites;
    }

    public void setFunctionalServerSupportedCipherSuites(
            List<CipherSuite> functionalServerSupportedCipherSuites) {
        this.functionalServerSupportedCipherSuites = functionalServerSupportedCipherSuites;
    }

    public ConnectionCreationReport getConnectionCreationReport() {
        return connectionCreationReport;
    }

    public void setConnectionCreationReport(ConnectionCreationReport connectionCreationReport) {
        this.connectionCreationReport = connectionCreationReport;
    }

    public FilterDirection getLockedFilterDirection() {
        return lockedFilterDirection;
    }

    public String getTargetName() {
        return targetName;
    }

    public List<NamedGroup> getClientSupportedNamedGroups() {
        return clientSupportedNamedGroups;
    }

    public void setClientSupportedNamedGroups(List<NamedGroup> clientSupportedNamedGroups) {
        this.clientSupportedNamedGroups = clientSupportedNamedGroups;
    }

    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        return clientSupportedSignatureAndHashAlgorithms;
    }

    public void setClientSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms) {
        this.clientSupportedSignatureAndHashAlgorithms = clientSupportedSignatureAndHashAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getServerRequestedSignatureAndHashAlgorithms() {
        return serverRequestedSignatureAndHashAlgorithms;
    }

    public void setServerRequestedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> serverRequestedSignatureAndHashAlgorithms) {
        this.serverRequestedSignatureAndHashAlgorithms = serverRequestedSignatureAndHashAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        return serverSupportedSignatureAndHashAlgorithms;
    }

    public void setServerSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms) {
        this.serverSupportedSignatureAndHashAlgorithms = serverSupportedSignatureAndHashAlgorithms;
    }

    public X509CertificateChain getExampleServerCertificateChain() {
        return exampleServerCertificateChain;
    }

    public void setExampleServerCertificateChain(
            X509CertificateChain exampleServerCertificateChain) {
        this.exampleServerCertificateChain = exampleServerCertificateChain;
    }

    public X509CertificateChain getExampleClientCertificateChain() {
        return exampleClientCertificateChain;
    }

    public void setExampleClientCertificateChain(
            X509CertificateChain exampleClientCertificateChain) {
        this.exampleClientCertificateChain = exampleClientCertificateChain;
    }

    public ProtocolVersion getDefaultSelectedProtocolVersion() {
        return defaultSelectedProtocolVersion;
    }

    public void setDefaultSelectedProtocolVersion(ProtocolVersion defaultSelectedProtocolVersion) {
        this.defaultSelectedProtocolVersion = defaultSelectedProtocolVersion;
    }

    public CipherSuite getDefaultSelectedCipherSuite() {
        return defaultSelectedCipherSuite;
    }

    public void setDefaultSelectedCipherSuite(CipherSuite defaultSelectedCipherSuite) {
        this.defaultSelectedCipherSuite = defaultSelectedCipherSuite;
    }

    public CompressionMethod getDefaultSelectedCompressionMethod() {
        return defaultSelectedCompressionMethod;
    }

    public void setDefaultSelectedCompressionMethod(
            CompressionMethod defaultSelectedCompressionMethod) {
        this.defaultSelectedCompressionMethod = defaultSelectedCompressionMethod;
    }

    public List<CipherSuite> getClientSupportedCipherSuites() {
        return clientSupportedCipherSuites;
    }

    public void setClientSupportedCipherSuites(List<CipherSuite> clientSupportedCipherSuites) {
        this.clientSupportedCipherSuites = clientSupportedCipherSuites;
    }

    public List<CompressionMethod> getClientSupportedCompressionMethods() {
        return clientSupportedCompressionMethods;
    }

    public void setClientSupportedCompressionMethods(
            List<CompressionMethod> clientSupportedCompressionMethods) {
        this.clientSupportedCompressionMethods = clientSupportedCompressionMethods;
    }

    public Set<ExtensionType> getNegotiatedExtensions() {
        return negotiatedExtensions;
    }

    public void setNegotiatedExtensions(Set<ExtensionType> negotiatedExtensions) {
        this.negotiatedExtensions = negotiatedExtensions;
    }

    public Set<ExtensionType> getClientSupportedExtensions() {
        return clientSupportedExtensions;
    }

    public void setClientSupportedExtensions(Set<ExtensionType> proposedExtensions) {
        this.clientSupportedExtensions = proposedExtensions;
    }

    public List<SrtpProtectionProfile> getClientSupportedProtectionProfiles() {
        return clientSupportedProtectionProfiles;
    }

    public void setClientSupportedProtectionProfiles(
            List<SrtpProtectionProfile> clientSupportedProtectionProfiles) {
        this.clientSupportedProtectionProfiles = clientSupportedProtectionProfiles;
    }

    public List<SrtpProtectionProfile> getServerSupportedProtectionProfiles() {
        return serverSupportedProtectionProfiles;
    }

    public void setServerSupportedProtectionProfiles(
            List<SrtpProtectionProfile> serverSupportedProtectionProfiles) {
        this.serverSupportedProtectionProfiles = serverSupportedProtectionProfiles;
    }

    public SrtpProtectionProfile getDefaultSelectedSrtpProtectionProfile() {
        return defaultSelectedSrtpProtectionProfile;
    }

    public void setDefaultSelectedSrtpProtectionProfile(
            SrtpProtectionProfile defaultSelectedSrtpProtectionProfile) {
        this.defaultSelectedSrtpProtectionProfile = defaultSelectedSrtpProtectionProfile;
    }

    public int getDefaultSignatureLength() {
        return defaultSignatureLength;
    }

    public void setDefaultSignatureLength(int defaultSignatureLength) {
        this.defaultSignatureLength = defaultSignatureLength;
    }

    public SignatureAndHashAlgorithm getDefaultServerSelectedSignatureAndHashAlgorithm() {
        return defaultServerSelectedSignatureAndHashAlgorithm;
    }

    public void setDefaultServerSelectedSignatureAndHashAlgorithm(
            SignatureAndHashAlgorithm defaultSelectedSignatureAndHashAlgorithm) {
        this.defaultServerSelectedSignatureAndHashAlgorithm =
                defaultSelectedSignatureAndHashAlgorithm;
    }

    public SignatureAndHashAlgorithm getDefaultClientSelectedSignatureAndHashAlgorithm() {
        return defaultClientSelectedSignatureAndHashAlgorithm;
    }

    public void setDefaultClientSelectedSignatureAndHashAlgorithm(
            SignatureAndHashAlgorithm defaultClientSelectedSignatureAndHashAlgorithm) {
        this.defaultClientSelectedSignatureAndHashAlgorithm =
                defaultClientSelectedSignatureAndHashAlgorithm;
    }

    public List<NamedGroup> getServerSupportedNamedGroups() {
        return serverSupportedNamedGroups;
    }

    public void setServerSupportedNamedGroups(List<NamedGroup> serverSupportedNamedGroups) {
        this.serverSupportedNamedGroups = serverSupportedNamedGroups;
    }

    public NamedGroup getDefaultSelectedNamedGroup() {
        return defaultSelectedNamedGroup;
    }

    public void setDefaultSelectedNamedGroup(NamedGroup defaultSelectedNamedGroup) {
        this.defaultSelectedNamedGroup = defaultSelectedNamedGroup;
    }

    public List<CipherSuite> getServerSupportedCipherSuites() {
        return serverSupportedCipherSuites;
    }

    public void setServerSupportedCipherSuites(List<CipherSuite> serverSupportedCipherSuites) {
        this.serverSupportedCipherSuites = serverSupportedCipherSuites;
    }

    public List<CompressionMethod> getServerSupportedCompressionMethods() {
        return serverSupportedCompressionMethods;
    }

    public void setServerSupportedCompressionMethods(
            List<CompressionMethod> serverSupportedCompressionMethods) {
        this.serverSupportedCompressionMethods = serverSupportedCompressionMethods;
    }

    public HashMap<PacketType, Integer> getProtocolsObservedInbound() {
        return protocolsObservedInbound;
    }

    public void setProtocolsObservedInbound(HashMap<PacketType, Integer> protocolsObservedInbound) {
        this.protocolsObservedInbound = protocolsObservedInbound;
    }

    public HashMap<PacketType, Integer> getProtocolsObservedOutbound() {
        return protocolsObservedOutbound;
    }

    public void setProtocolsObservedOutbound(
            HashMap<PacketType, Integer> protocolsObservedOutbound) {
        this.protocolsObservedOutbound = protocolsObservedOutbound;
    }

    public Set<ExtensionType> getServerSupportedExtensions() {
        return serverSupportedExtensions;
    }

    public void setServerSupportedExtensions(Set<ExtensionType> serverSupportedExtensions) {
        this.serverSupportedExtensions = serverSupportedExtensions;
    }

    public void addPostDtlsReport(MediaReport report) {
        postDtlsReports.add(report);
    }

    protected List<MediaReport> getPostDtlsReports() {
        return postDtlsReports;
    }

    public int getDtlsSessionsPerCall() {
        return dtlsSessionsPerCall;
    }

    public void setDtlsSessionsPerCall(int dtlsSessionsPerCall) {
        this.dtlsSessionsPerCall = dtlsSessionsPerCall;
    }

    @Override
    public synchronized String toString() {
        return new WebRtcReportPrinter(
                        ScannerDetail.NORMAL,
                        DefaultPrintingScheme.getDefaultPrintingScheme(),
                        false,
                        this)
                .getFullReport();
    }

    @Override
    public void serializeToJson(OutputStream OutputStream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serializeToJson'");
    }

    public List<SNIEntry> getClientSNIEntryList() {
        return clientSNIEntryList;
    }

    public void setClientSNIEntryList(List<SNIEntry> clientSNIEntryList) {
        this.clientSNIEntryList = clientSNIEntryList;
    }
}
