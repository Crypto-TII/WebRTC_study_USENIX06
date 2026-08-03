/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2023 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.action;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.TightReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.CommonForwardAction;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.util.MimicryEngine;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/** This action forwards the certificate message it then injects */
@XmlRootElement(name = "DynamicCertificateInjectionAction")
public class DynamicCertificateInjectionAction extends CommonForwardAction {

    private boolean injectRealFirst;

    private boolean useServerChain;

    @SuppressWarnings("unused")
    private DynamicCertificateInjectionAction() {}

    public DynamicCertificateInjectionAction(
            String receiveFromAlias,
            String forwardToAlias,
            boolean injectRealFirst,
            boolean useServerChain) {
        super(receiveFromAlias, forwardToAlias);
        this.injectRealFirst = injectRealFirst;
        this.useServerChain = useServerChain;
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Dynamic Certificate Injection Action:\n");
            sb.append("\tMessages:");
            if (getSentMessages() != null) {
                for (ProtocolMessage message : getSentMessages()) {
                    sb.append(message.toCompactString());
                    sb.append(", ");
                }
                sb.append("\n");
            } else {
                sb.append("null (no messages set)");
            }
        } else {
            sb = new StringBuilder("Dynamic Certificate Injection Action: (not executed)\n");
        }

        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((getSentMessages() != null) && (!getSentMessages().isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage message : getSentMessages()) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    protected List<LayerConfiguration<?>> createReceiveConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getReceiveFromAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new TightReceiveLayerConfiguration(
                        ImplementedLayers.MESSAGE, new CertificateMessage()));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), false, getActionOptions(), configurationList);
    }

    @Override
    protected List<LayerConfiguration<?>> createSendConfiguration(
            State state, LayerStackProcessingResult receivedResult) {

        CertificateMessage originalCertificateMessage = null;
        LayerProcessingResult<?> messageLayerResult =
                receivedResult.getResultForLayer(ImplementedLayers.MESSAGE);
        for (DataContainer message : messageLayerResult.getUsedContainers()) {
            if (message instanceof CertificateMessage) {
                originalCertificateMessage = (CertificateMessage) message;
            }
        }
        if (originalCertificateMessage == null) {
            throw new RuntimeException("No CertificateMessage found in received messages");
        }
        X509CertificateChain originalChain =
                useServerChain
                        ? state.getTlsContext(receiveFromAlias).getServerCertificateChain()
                        : state.getTlsContext(receiveFromAlias).getClientCertificateChain();

        List<X509CertificateConfig> configList = new LinkedList<>();

        // populate list with placeholders
        for (int i = 0; i < originalChain.size(); i++) {
            configList.add(new X509CertificateConfig());
        }

        // Create chain that mimics the original but uses our keys
        X509CertificateChain mimicryChain =
                MimicryEngine.createMimicryCertificateChain(configList, originalChain);

        // inject the original certificates from the last chain observed into our chain
        if (injectRealFirst) {
            // add the original certificates to the beginning of the chain
            for (int i = originalChain.size() - 1; i >= 0; i--) {
                mimicryChain.addCertificate(0, originalChain.getCertificate(i));
            }
        } else {
            // add the original certificates to the chain at the end
            for (int i = 0; i < originalChain.size(); i++) {
                mimicryChain.addCertificate(originalChain.getCertificate(i));
            }
        }

        // set the config from here on out to use our custom chain
        // we can not explicitly set the CertificateMessage's certificates because it is overwritten
        // by config values...
        state.getTlsContext(getForwardToAlias())
                .getConfig()
                .setDefaultExplicitCertificateChain(mimicryChain);

        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.MESSAGE, new CertificateMessage()));

        return ActionHelperUtil.sortAndAddOptions(
                state.getTlsContext(getForwardToAlias()).getLayerStack(),
                true,
                getActionOptions(),
                configurationList);
    }
}
