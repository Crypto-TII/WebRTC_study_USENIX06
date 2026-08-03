/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2025 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.action;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.dtlsproxy.probes.dtls.DtlsProbe;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.X509CertificateChainBuilder;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DynamicCertificateInjectionActionTest {

    private DynamicCertificateInjectionAction actionRealFirst;
    private DynamicCertificateInjectionAction actionFakeFirst;
    private LayerStackProcessingResult receivedResult;
    private X509CertificateChain chain;

    private State state1;
    private State state2;

    @BeforeEach
    void setUp() {
        actionRealFirst =
                new DynamicCertificateInjectionAction(
                        DtlsProbe.ATTACKER_TO_SERVER_CONNECTION,
                        DtlsProbe.CLIENT_TO_ATTACKER_CONNECTION,
                        true,
                        true);
        actionFakeFirst =
                new DynamicCertificateInjectionAction(
                        DtlsProbe.ATTACKER_TO_SERVER_CONNECTION,
                        DtlsProbe.CLIENT_TO_ATTACKER_CONNECTION,
                        false,
                        true);
        List<AliasedConnection> aliasedConnections = new LinkedList<>();
        aliasedConnections.add(new InboundConnection(DtlsProbe.ATTACKER_TO_SERVER_CONNECTION));
        aliasedConnections.add(new OutboundConnection(DtlsProbe.CLIENT_TO_ATTACKER_CONNECTION));
        WorkflowTrace trace = new WorkflowTrace(aliasedConnections);
        state1 = new State(new Config(), trace);
        state2 = new State(new Config(), trace);

        List<LayerProcessingResult<?>> results = new LinkedList<>();
        List<ProtocolMessage> containers = new LinkedList<>();
        CertificateMessage certificateMessage = new CertificateMessage();
        containers.add(certificateMessage);
        X509CertificateConfig certConfig = new X509CertificateConfig();
        certConfig.setPublicKeyType(X509PublicKeyType.RSA);
        certConfig.setRsaModulus(
                new BigInteger(
                        "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        X509CertificateConfig certConfig2 = new X509CertificateConfig();
        certConfig2.setPublicKeyType(X509PublicKeyType.RSA);
        certConfig2.setRsaModulus(
                new BigInteger(
                        "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"));

        chain =
                new X509CertificateChainBuilder()
                        .buildChain(certConfig, certConfig2)
                        .getCertificateChain();
        state1.getTlsContext(DtlsProbe.ATTACKER_TO_SERVER_CONNECTION)
                .setClientCertificateChain(chain);
        state1.getTlsContext(DtlsProbe.ATTACKER_TO_SERVER_CONNECTION)
                .setServerCertificateChain(chain);
        state2.getTlsContext(DtlsProbe.ATTACKER_TO_SERVER_CONNECTION)
                .setClientCertificateChain(chain);
        state2.getTlsContext(DtlsProbe.ATTACKER_TO_SERVER_CONNECTION)
                .setServerCertificateChain(chain);

        results.add(new LayerProcessingResult(containers, ImplementedLayers.MESSAGE, true));
        receivedResult = new LayerStackProcessingResult(results);
    }

    @Test
    void testCreateSendConfiguration() {
        actionFakeFirst.createSendConfiguration(state1, receivedResult);
        actionRealFirst.createSendConfiguration(state2, receivedResult);

        List<CertificateBytes> certBytes1 = state1.getConfig().getDefaultExplicitCertificateChain();
        List<CertificateBytes> certBytes2 = state2.getConfig().getDefaultExplicitCertificateChain();

        assertEquals(4, certBytes1.size());
        assertEquals(4, certBytes2.size());

        assertArrayEquals(certBytes1.get(0).getBytes(), certBytes2.get(2).getBytes());
        assertArrayEquals(certBytes1.get(1).getBytes(), certBytes2.get(3).getBytes());
        assertArrayEquals(certBytes2.get(0).getBytes(), certBytes1.get(2).getBytes());
        assertArrayEquals(certBytes2.get(1).getBytes(), certBytes1.get(3).getBytes());
    }
}
