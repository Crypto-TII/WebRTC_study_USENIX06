/*
 * WebRTC-DTLS-Analysis-Proxy
 *
 * Copyright 2022-2024 Technology Innovation Institute (TII), Abu Dhabi
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.dtlsproxy.action;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.CommonForwardAction;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ForwardServerFlightAction extends CommonForwardAction {

    protected boolean mustHaveCertificateRequest = false;
    protected boolean injectCertificateRequestIfMissing = false;

    public ForwardServerFlightAction() {}

    public ForwardServerFlightAction(
            String receiveFromAlias,
            String forwardToAlias,
            boolean mustHaveCertificateRequest,
            boolean injectCertificateRequestIfMissing) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.mustHaveCertificateRequest = mustHaveCertificateRequest;
        this.injectCertificateRequestIfMissing = injectCertificateRequestIfMissing;
    }

    public boolean isMustHaveCertificateRequest() {
        return mustHaveCertificateRequest;
    }

    public void setMustHaveCertificateRequest(boolean mustHaveCertificateRequest) {
        this.mustHaveCertificateRequest = mustHaveCertificateRequest;
    }

    @Override
    protected List<LayerConfiguration<?>> createReceiveConfiguration(State state) {
        ProtocolMessage tempMessage;
        List<ProtocolMessage> expectedMessages = new LinkedList<>();
        expectedMessages.add(new ServerHelloMessage());
        tempMessage = new CertificateMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new ECDHEServerKeyExchangeMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new DHEServerKeyExchangeMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new CertificateRequestMessage();
        tempMessage.setRequired(mustHaveCertificateRequest);
        expectedMessages.add(tempMessage);
        expectedMessages.add(new ServerHelloDoneMessage());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificReceiveLayerConfiguration<>(
                        ImplementedLayers.MESSAGE, expectedMessages));
        return ActionHelperUtil.sortAndAddOptions(
                state.getTlsContext(receiveFromAlias).getLayerStack(),
                false,
                getActionOptions(),
                configurationList);
    }

    @Override
    protected List<LayerConfiguration<?>> createSendConfiguration(
            State state, LayerStackProcessingResult receivedResult) {
        TlsContext tlsContext = state.getTlsContext(getForwardToAlias());
        List<ProtocolMessage> receivedMessages = getReceivedMessages();
        boolean hasCertificateRequest = false;
        boolean hasServerHelloDone = false;
        for (ProtocolMessage message : receivedMessages) {
            message.setShouldPrepareDefault(
                    false); // Do not recompute the messages on the message layer
            if (message instanceof CertificateRequestMessage) {
                hasCertificateRequest = true;
            }
            if (message instanceof ServerHelloDoneMessage) {
                hasServerHelloDone = true;
            }
        }
        if (!hasCertificateRequest && injectCertificateRequestIfMissing && hasServerHelloDone) {
            // Find position where we need to inject the CertificateRequestMessage
            int position = 0;
            for (int i = 0; i < receivedMessages.size(); i++) {
                if (receivedMessages.get(i) instanceof ServerHelloMessage) {
                    position = i + 1;
                }
                if (receivedMessages.get(i) instanceof CertificateMessage) {
                    position = i + 1;
                }
                if (receivedMessages.get(i) instanceof ServerKeyExchangeMessage) {
                    position = i + 1;
                }
            }
            receivedMessages.add(
                    position,
                    new CertificateRequestMessage()); // Notably this message will be prepared
        }
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificSendLayerConfiguration<>(ImplementedLayers.MESSAGE, receivedMessages));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), true, getActionOptions(), configurationList);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Forward Server Flight Action:\n");
        sb.append("Receive from alias: ").append(receiveFromAlias).append("\n");
        sb.append("\tExpected: any valid server flight");
        sb.append("\n\tActual:");
        if ((getReceivedMessages() != null) && (!getReceivedMessages().isEmpty())) {
            for (ProtocolMessage message : getReceivedMessages()) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        sb.append("Forwarded to alias: ").append(forwardToAlias).append("\n");
        if (getSentMessages() != null) {
            sb.append("\t");
            for (ProtocolMessage message : getSentMessages()) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
            sb.append("\n");
        } else {
            sb.append("null (no messages set)");
        }
        return sb.toString();
    }
}
